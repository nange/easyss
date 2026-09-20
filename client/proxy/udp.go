package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/util/bytespool"
	"github.com/txthinking/socks5"
)

// isDNSQueryMsg 报告 msg 是否为一次待拦截的 DNS 查询：任意 qtype、必须带
// Question 且不是响应。UDP 与 TCP 两条 DNS 拦截路径共用同一判定，否则同一
// 域名的 MX/TXT/HTTPS 等查询会出现"UDP 按目标 IP 直连出网、TCP 按域名走隧道"
// 的分裂行为。
//
// 它刻意比 util.IsDNSRequest（仅 A/AAAA）宽松：后者还被服务端 nextproxy 的
// 动态域名学习使用，在那里放宽会改变拦截门控（例如让 MX 应答也进入学习路径）。
func isDNSQueryMsg(msg *dns.Msg) bool {
	return msg != nil && len(msg.Question) > 0 && !msg.Response
}

func (s *Socks5Server) handleUDP(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram) error {
	src := clientAddr.String()
	dst := d.Address()

	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		// 畸形数据报目标：直接丢弃，而不是用一个服务器反正会拒绝的空目标
		// 打开交换。
		log.Debug("[UDP] malformed datagram target", "src", src, "target", dst, "err", err)
		return nil
	}
	if s.disableQUIC && port == "443" {
		return nil
	}

	if s.router.ShouldIPV6Disable() && util.IsIPV6(host) {
		log.Warn("[UDP] ipv6 target rejected, ipv6 disabled", "target", dst)
		return nil
	}

	msg := &dns.Msg{}
	if err := msg.Unpack(d.Data); err == nil && isDNSQueryMsg(msg) {
		return s.handleDNS(srv, clientAddr, d, msg)
	}

	return s.handleRegularUDP(srv, clientAddr, d, dst)
}

func (s *Socks5Server) handleDNS(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, msg *dns.Msg) error {
	question := msg.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")
	qtype := dns.TypeToString[question.Qtype]

	rule := s.router.MatchHostRule(domain)
	if rule == router.HostRuleBlock {
		log.Info("[DNS_BLOCK] blocked", "domain", domain, "qtype", qtype)
		return responseBlockedDNSMsg(srv.UDPConn, clientAddr, msg, d.Address())
	}

	// 对代理服务器自身的域名绝不走代理路径：打开隧道来应答查询会需要再次解析
	// 服务器域名，形成循环依赖。回退到直连路径（绑定到物理接口，绕过 TUN）。
	isServerDomain := s.isServerDomain(domain)
	if isServerDomain {
		log.Info("[DNS_SERVER_DOMAIN] direct", "domain", domain, "qtype", qtype)
	}
	isDirect := isServerDomain || rule == router.HostRuleDirect

	if cached := s.dnsCache.Get(question.Name, qtype, isDirect); cached != nil {
		log.Info("[DNS_CACHE] hit", "domain", domain, "qtype", qtype, "direct", isDirect)
		if s.router.ShouldIPV6Disable() && cached.Question[0].Qtype == dns.TypeAAAA {
			cached.Answer = nil
		}
		cached.Id = msg.Id
		return responseDNSMsg(srv.UDPConn, clientAddr, cached, d.Address())
	}

	if isDirect {
		log.Info("[DNS_DIRECT]", "domain", domain, "qtype", qtype)
		stats.RecordDNSDirectQuery()
		return s.directDNSQuery(srv, clientAddr, d, msg, domain)
	}

	log.Info("[DNS_PROXY]", "domain", domain, "qtype", qtype)
	stats.RecordDNSProxyQuery()
	return s.proxyDNSQuery(srv, clientAddr, d, msg, domain)
}

func (s *Socks5Server) directDNSQuery(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, msg *dns.Msg, domain string) error {
	resp, err := s.resolveDirectDNS(msg, domain, d.Address())
	if err != nil {
		log.Error("[DNS_DIRECT]", "domain", domain, "err", err)
		return err
	}

	qtype := dns.TypeToString[msg.Question[0].Qtype]
	log.Info("[DNS_DIRECT] result", "domain", domain, "qtype", qtype, "answers", util.DNSAnswerStrings(resp))

	resp.Id = msg.Id
	return responseDNSMsg(srv.UDPConn, clientAddr, resp, d.Address())
}

// resolveDirectDNS 不经隧道直接解析 msg：优先用客户端请求的 DNS 服务器
// （reqServer，可能为空或不可用），否则用内置公共 DNS、系统 DNS 兜底；并完成
// AAAA 剥离、缓存与自定义直连域名学习。应答 ID 由调用方改写。
// UDP 直连 DNS 与 TCP DNS 拦截共用。
//
// reqServer 让"客户端显式指定了解析器"这一信息不被丢弃：否则发往内网/企业
// 解析器的查询会被转投公共 DNS 而拿到错误答案。仅在请求的服务器是明确的单播
// 地址时才采用（未指定/多播地址，以及 ipv6_rule=disable 下的 IPv6 地址一律
// 忽略，这些地址永远拨不通）；reqServer 失败时仍回落到内置列表，保持既有韧性。
// 多个候选由一个共享超时预算并发竞争（见 exchangeDirectDNSFromList），不会串行
// 叠加延迟。
func (s *Socks5Server) resolveDirectDNS(msg *dns.Msg, domain, reqServer string) (*dns.Msg, error) {
	try := func(servers []string) (*dns.Msg, error) {
		return s.exchangeDirectDNSFromList(msg, servers)
	}

	var resp *dns.Msg
	var err error
	if s.usableDirectDNSServer(reqServer) {
		resp, err = s.exchangeDirectDNSFromList(msg, append([]string{reqServer}, config.DirectDNSServers...))
	} else {
		// 兜底列表必须是过滤后的可用上游：QueryWithBuiltinFirst 依据它是否为
		// 空来决定要不要熔断内置服务器（见 easydns.QueryWithBuiltinFirst）。
		fallback := s.filterDNSUpstreams(easydns.SystemDNSServers())
		resp, err = easydns.QueryWithBuiltinFirst(config.DirectDNSServers, fallback, try)
	}
	if err != nil {
		return nil, err
	}
	if s.router.ShouldIPV6Disable() && msg.Question[0].Qtype == dns.TypeAAAA {
		resp.Answer = nil
	}
	_ = s.dnsCache.Set(resp, true)
	s.learnDNSAnswers(resp, domain, true)
	return resp, nil
}

// usableDirectDNSServer 报告 addr 是否可作为直连解析的目标：必须是可拨号的
// 单播地址。未指定（0.0.0.0/::）与多播/广播地址永远不可用；ipv6_rule=disable
// 时 IPv6 上游也要忽略（exchangeDirectDNSFromList 同样会过滤，这里只是提前
// 让出内置兜底路径）。回环地址是允许的：那可能正是客户端配置的本地解析器
// （本机 DNS 转发服务器），拨过去仍能拿到应答，只是多一跳。
func (s *Socks5Server) usableDirectDNSServer(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if s.router.ShouldIPV6Disable() && util.IsIPV6(host) {
		return false
	}
	return true
}

// learnDNSAnswers 依据自定义直连/代理域名规则，从应答中学习 A/AAAA/CNAME，
// 供后续连接按 IP 或域名路由。UDP 与 TCP DNS 路径共用。
func (s *Socks5Server) learnDNSAnswers(msg *dns.Msg, domain string, isDirect bool) {
	if msg == nil {
		return
	}
	if isDirect {
		if !s.router.IsCustomDirectDomain(domain) {
			return
		}
		for _, ans := range msg.Answer {
			switch a := ans.(type) {
			case *dns.A:
				s.router.AddDirectIP(a.A.String())
			case *dns.AAAA:
				s.router.AddDirectIP(a.AAAA.String())
			case *dns.CNAME:
				s.router.AddDirectDomain(strings.TrimSuffix(a.Target, "."))
			}
		}
		return
	}
	if !s.router.IsCustomProxyDomain(domain) {
		return
	}
	util.ForEachDNSAnswer(msg, func(kind, value string) {
		if kind == "CNAME" {
			s.router.AddProxyDomain(value)
			return
		}
		s.router.AddProxyIP(value)
	})
}

// filterDNSUpstreams 丢弃当前规则下无法拨通的上游：ipv6_rule=disable 时
// IPv6 地址永远拨不通。它同时被兜底列表的构建（resolveDirectDNS）与实际交换
// （exchangeDirectDNSFromList）使用，使"是否存在可用兜底"与"真正会被尝试的
// 上游"是同一份列表。
func (s *Socks5Server) filterDNSUpstreams(servers []string) []string {
	var candidates []string
	for _, addr := range servers {
		if s.router.ShouldIPV6Disable() && util.IsIPV6Addr(addr) {
			continue
		}
		candidates = append(candidates, addr)
	}
	return candidates
}

// exchangeDirectDNSFromList 依次用给定的 DNS 服务器交换 msg。内置优先的回退
// （包括熔断器冷却时间）由调用方通过 easydns.QueryWithBuiltinFirst 施加。
func (s *Socks5Server) exchangeDirectDNSFromList(msg *dns.Msg, servers []string) (*dns.Msg, error) {
	candidates := s.filterDNSUpstreams(servers)
	if len(candidates) == 0 {
		return nil, errors.New("no dns server available")
	}

	// 并发查询每个上游并取第一个成功结果。串行扫描时，一个卡住的上游会把查询
	// 拖到单服务器超时上限，而每个数据报的处理 goroutine 都会阻塞在整个等待
	// 期间——DNS 故障时 goroutine 就会越积越多。整个查询共享一个超时预算。
	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
	defer cancel()

	type result struct {
		resp *dns.Msg
		err  error
	}
	ch := make(chan result, len(candidates))
	for _, addr := range candidates {
		go func(addr string) {
			resp, err := s.exchangeDirectDNS(ctx, msg, addr)
			ch <- result{resp: resp, err: err}
		}(addr)
	}

	var lastErr error
	for range candidates {
		select {
		case r := <-ch:
			if r.err == nil {
				return r.resp, nil
			}
			lastErr = r.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no dns server available")
	}
	return nil, lastErr
}

func (s *Socks5Server) exchangeDirectDNS(ctx context.Context, msg *dns.Msg, addr string) (*dns.Msg, error) {
	conn, err := s.directDialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck

	_ = conn.SetDeadline(time.Now().Add(s.dialTimeout))
	dnsConn := &dns.Conn{Conn: conn, UDPSize: 8192}
	if err := dnsConn.WriteMsg(msg); err != nil {
		return nil, err
	}
	return dnsConn.ReadMsg()
}

func (s *Socks5Server) proxyDNSQuery(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, msg *dns.Msg, domain string) error {
	// upstream 是本代理解析查询的位置；客户端请求的是其自身解析器所配置的
	// 服务器，而应答必须伪装成来自该地址（d.Address()），与其他所有 DNS 分支
	// 一致。如果改用 upstream 来封装应答，透明 NAT（tun2socks）会把它丢弃：
	// 流是按客户端的目标来标识的，声称来自不同服务器的数据报永远不会匹配，
	// 查询就会看起来没有得到应答。
	upstream := config.ProxyDNSServer
	key := clientAddr.String() + "_" + upstream

	ue, created, err := s.getOrCreateUDPExchange(context.Background(), key, upstream, d.Data)
	if err != nil {
		log.Error("[UDP_PROXY] open exchange", "dst", upstream, "err", err)
		return err
	}
	if created {
		go s.receiveLoop(ue, srv, clientAddr, d.Address(), key, s.dnsRespTimeout)
		return nil // 第一个载荷已在握手中发送
	}

	if err := ue.Send(d.Data); err != nil {
		log.Error("[UDP_PROXY] send", "err", err)
		s.udpMu.Lock()
		delete(s.udpExch, key)
		s.udpMu.Unlock()
		ue.Close() //nolint:errcheck
		return err
	}
	return nil
}

// maxUDPExchanges 限制并发代理 UDP 交换的数量。每个交换占有一条 HTTP/2 流、
// 一个 receiveLoop goroutine 和一个 shaper；按（客户端地址，目标）做键意味着：
// 若客户端每个数据报都使用新的临时 UDP 源端口（Go 的 net.Resolver、某些 curl
// 构建），就会在空闲窗口内累积数百个交换。达到上限时，空闲最久的交换被驱逐。
const maxUDPExchanges = 128

// getOrCreateUDPExchange 返回 key 对应的现有 UDPExchange，不存在时通过
// OpenUDPExchange 创建。firstPayload 非空且交换为新创建时，会被合并进引导记录
// （省去一次 RTT）。若交换已存在，则忽略 firstPayload。若本次调用创建了交换，
// created 为 true，调用方绝不能为第一个载荷调用 ue.Send（它已在握手中发送）。
// ctx 约束交换的创建过程（拨号 + TLS + 引导），供需要硬截止时间的调用方使用
// （例如启动预热）；DNS 路径传入 context.Background()，改而依赖自己的响应超时。
//
// 同一 key 的并发创建通过 singleflight 组去重：第一个调用方执行（较慢的）
// OpenUDPExchange，并发等待者阻塞并复用其结果，因此每个 (client, target) 流
// 恰好只有一条 HTTP/2 流和一个 receiveLoop。
func (s *Socks5Server) getOrCreateUDPExchange(ctx context.Context, key, dst string, firstPayload []byte) (ue *UDPExchange, created bool, err error) {
	s.udpMu.RLock()
	existing, ok := s.udpExch[key]
	s.udpMu.RUnlock()
	if ok {
		return existing, false, nil
	}

	// 在创建前强制交换数量上限。其他 key 正在创建中的数量计入上限；本次调用
	// 自身的创建尚未登记（flight 函数在检查之后才递增 udpInflightCount），
	// 与 singleflight 之前的语义一致——那时工厂条目也是在检查之后才插入。
	var evicted *UDPExchange
	s.udpMu.Lock()
	if len(s.udpExch)+int(s.udpInflightCount.Load()) >= maxUDPExchanges {
		evicted = s.evictOldestExchangeLocked()
	}
	s.udpMu.Unlock()
	// 在锁外关闭被驱逐的交换：Close 会通过 HTTP/2 流冲刷一个 FIN（一次 io.Pipe
	// 写入），可能因传输层背压而阻塞——此时持有 s.udpMu 会冻结所有 UDP 处理。
	// closeOnce 保证它与 receiveLoop 自身的延迟 Close 并发时是安全的。
	if evicted != nil {
		evicted.Close() //nolint:errcheck
	}

	v, err, shared := s.udpExchangeSF.Do(key, func() (any, error) {
		s.udpInflightCount.Add(1)
		defer s.udpInflightCount.Add(-1)

		ue, err := s.handler.OpenUDPExchange(ctx, dst, s.method, firstPayload)
		if err != nil {
			return nil, err
		}
		// 交换创建过程中服务器已关闭：立即关闭它，使流及其 receiveLoop 不会
		// 泄漏到关闭之后（清理循环已经退出）。
		if s.closing.Load() {
			ue.Close() //nolint:errcheck
			return nil, errSocksServerClosed
		}
		return ue, nil
	})
	if err != nil {
		return nil, false, err
	}
	ue = v.(*UDPExchange)
	if s.closing.Load() {
		// 服务器在 flight 结束之后、交换登记之前被关闭。创建者（shared == false）
		// 拥有该交换并必须关闭它（它尚未在 map 中，因此 Close 的 map 扫描无法
		// 回收它）；等待者只报告错误。
		if !shared {
			ue.Close() //nolint:errcheck
		}
		return nil, false, errSocksServerClosed
	}
	// 每个调用方（创建者与等待者）登记同一个指针是幂等的，并让等待者
	// 能用它自己的 ue.Send 发送首个载荷，而不会丢失。
	s.udpMu.Lock()
	s.udpExch[key] = ue
	s.udpMu.Unlock()
	// created 报告本次调用的 firstPayload 是否被合并进引导记录：只有创建者的
	// 载荷被合并了（shared == false）。
	return ue, !shared, nil
}

var errSocksServerClosed = errors.New("socks5 udp server closed")

// evictOldestExchangeLocked 选择空闲最久的交换并将其从 map 中移除，把存活交换
// 数量限制在 maxUDPExchanges 以内。被驱逐的交换返回时并未关闭：调用方必须在
// 释放 s.udpMu 后关闭它，因为 UDPExchange.Close 会通过 HTTP/2 流冲刷一个 FIN
// （一次 io.Pipe 写入），可能因传输层背压而阻塞——此时持有 s.udpMu 会冻结所有
// UDP 处理。closeOnce 保证延迟的关闭与 receiveLoop 自身的 Close 并发时是安全的。
func (s *Socks5Server) evictOldestExchangeLocked() *UDPExchange {
	var oldestKey string
	var oldestTime time.Time
	for k, ue := range s.udpExch {
		last := ue.LastSeen()
		if oldestKey == "" || last.Before(oldestTime) {
			oldestKey, oldestTime = k, last
		}
	}
	if oldestKey == "" {
		return nil
	}
	log.Debug("[UDP_PROXY] exchange cap reached, evicting oldest idle", "key", oldestKey)
	evicted := s.udpExch[oldestKey]
	delete(s.udpExch, oldestKey)
	return evicted
}

func (s *Socks5Server) receiveLoop(ue *UDPExchange, srv *socks5.Server, clientAddr *net.UDPAddr, target, key string, respTimeout time.Duration) {
	// 代理 DNS 交换的读空闲超时：查询已经发送（Send 会刷新 lastSeen，所以对于
	// 不断重试而上游一直沉默的客户端，默认 60 秒的空闲回收器永远不会触发），因此
	// 服务器长时间沉默意味着上游 DNS 没有应答。关闭交换，使流和 goroutine 不会
	// 堆积；下一个查询会透明地重建它。任何收到的数据报都会重置该定时器。
	// respTimeout <= 0 时禁用该机制（非 DNS 的 UDP）。
	var timer *time.Timer
	if respTimeout > 0 {
		timer = time.AfterFunc(respTimeout, func() {
			log.Debug("[UDP_PROXY] dns response timeout, closing exchange", "key", key, "target", target)
			ue.Close() //nolint:errcheck // closeOnce 使其与并发的 Close 之间保持安全
		})
		defer timer.Stop()
	}
	defer func() {
		s.udpMu.Lock()
		delete(s.udpExch, key)
		s.udpMu.Unlock()
		ue.Close() //nolint:errcheck
	}()

	for {
		data, err := ue.Receive()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Debug("[UDP_PROXY] receive", "err", err)
			}
			return
		}
		if timer != nil {
			timer.Reset(respTimeout)
		}

		msg := &dns.Msg{}
		if err := msg.Unpack(data); err == nil && util.IsDNSResponse(msg) {
			if s.router.ShouldIPV6Disable() && msg.Question[0].Qtype == dns.TypeAAAA {
				msg.Answer = nil
				if packed, packErr := msg.Pack(); packErr == nil {
					data = packed
				}
			}
			_ = s.dnsCache.Set(msg, false)

			domain := strings.TrimSuffix(msg.Question[0].Name, ".")
			qtype := dns.TypeToString[msg.Question[0].Qtype]
			log.Info("[DNS_PROXY] result", "domain", domain, "qtype", qtype, "answers", util.DNSAnswerStrings(msg))

			s.learnDNSAnswers(msg, domain, false)
		}
		s.sendToClient(srv, clientAddr, data, target)
	}
}

func (s *Socks5Server) sendToClient(srv *socks5.Server, clientAddr *net.UDPAddr, data []byte, target string) {
	a, addr, port, err := socks5.ParseAddress(target)
	if err != nil {
		return
	}
	if a == socks5.ATYPDomain {
		addr = addr[1:]
	}
	resp := socks5.NewDatagram(a, addr, port, data)
	if _, err := srv.UDPConn.WriteToUDP(resp.Bytes(), clientAddr); err != nil {
		log.Debug("[UDP] write to client", "err", err)
	}
}

func (s *Socks5Server) handleRegularUDP(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, dst string) error {
	host, _, err := net.SplitHostPort(dst)
	if err != nil {
		return err
	}

	switch s.router.ClassifyHost(host).Rule {
	case router.HostRuleBlock:
		log.Info("[UDP_BLOCK] blocked", "host", host, "target", dst)
		return nil
	case router.HostRuleDirect:
		log.Info("[UDP_DIRECT]", "target", dst)
		return s.directUDPRelay(srv, clientAddr, d, dst)
	case router.HostRuleProxy:
		log.Info("[UDP_PROXY]", "target", dst)
		return s.proxyUDPRelay(srv, clientAddr, d, dst)
	}
	return nil
}

func (s *Socks5Server) directUDPRelay(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, dst string) error {
	key := "direct_" + clientAddr.String() + "_" + dst

	s.udpMu.RLock()
	dc, ok := s.directUDP[key]
	s.udpMu.RUnlock()

	if !ok {
		var err error
		dc, err = s.getOrCreateDirectUDPSession(srv, clientAddr, dst, key)
		if err != nil {
			return err
		}
	}

	dc.lastSeen.Store(time.Now().UnixNano())
	_, err := dc.conn.Write(d.Data)
	return err
}

// getOrCreateDirectUDPSession 返回 key 对应的直连 UDP 会话，不存在时创建其
// socket 与读取循环。同一 key 的并发创建者通过 singleflight 组去重（镜像代理
// 路径）：第一个调用方拨号，其余调用方等待并复用其结果，因此每个 (client,
// target) 流恰好只有一个 socket 和一个读取循环。没有去重时，同一流的两个数据报
// 被并发处理，都会错过 map 查询并各自拨号：一个 socket 被孤立（连同其读取
// goroutine 一起泄漏，直到读空闲截止时间），而孤立者的清理随后删除了存活的
// map 条目，导致该流每隔约 udpIdleTimeout 就要更换一个新 socket。
func (s *Socks5Server) getOrCreateDirectUDPSession(srv *socks5.Server, clientAddr *net.UDPAddr, dst, key string) (*directUDPConn, error) {
	s.udpMu.RLock()
	dc, ok := s.directUDP[key]
	s.udpMu.RUnlock()
	if ok {
		return dc, nil
	}

	v, err, _ := s.directUDPSF.Do(key, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
		rc, err := s.directDialContext(ctx, "udp", dst)
		cancel()
		if err != nil {
			return nil, err
		}

		// 拨号期间服务器已关闭：关闭 socket，使会话及其读取循环不会泄漏到
		// 关闭之后（清理循环已经退出）。
		if s.closing.Load() {
			rc.Close() //nolint:errcheck
			return nil, errSocksServerClosed
		}

		dc := &directUDPConn{conn: rc}
		dc.lastSeen.Store(time.Now().UnixNano())

		s.udpMu.Lock()
		if s.closing.Load() {
			// 在与登记相同的锁下重新检查：与拨号竞争的 Close 已经执行过它的
			// 扫描，因此之后再插入的条目永远不会被回收（清理循环与读取循环都
			// 拒绝触碰正在关闭的服务器）。
			s.udpMu.Unlock()
			rc.Close() //nolint:errcheck
			return nil, errSocksServerClosed
		}
		// 与代理路径一样强制会话数量上限：否则向许多不同直连目标发送 UDP 的
		// 客户端会为每个流创建一个 socket 加一个 goroutine，且只能靠 30 秒的
		// 清理定时器回收。
		var evicted *directUDPConn
		if len(s.directUDP) >= maxUDPExchanges {
			evicted = s.evictOldestDirectUDPLocked()
		}
		s.directUDP[key] = dc
		s.udpMu.Unlock()

		if evicted != nil {
			// 关闭 socket 会使被驱逐会话的读取循环返回，从而按身份移除它自己
			// （已经被删除）的 map 条目。
			evicted.conn.Close() //nolint:errcheck
		}

		go s.directUDPReadLoop(srv, clientAddr, dst, key, dc)

		return dc, nil
	})
	if err != nil {
		return nil, err
	}
	dc = v.(*directUDPConn)
	// 服务器在 flight 结束后被关闭：创建者已经登记了会话，因此 Close 的 map
	// 扫描或读取循环自身的退出会回收它；等待者只报告错误。
	if s.closing.Load() {
		return nil, errSocksServerClosed
	}
	return dc, nil
}

// evictOldestDirectUDPLocked 选择空闲最久的直连 UDP 会话并将其从 map 中移除，
// 把存活会话数量限制在 maxUDPExchanges 以内。调用方必须在释放 s.udpMu 后关闭
// 返回的 socket：关闭它会解除会话读取循环的阻塞，而读取循环自己会加锁。
func (s *Socks5Server) evictOldestDirectUDPLocked() *directUDPConn {
	var oldestKey string
	var oldestTime time.Time
	for k, dc := range s.directUDP {
		last := time.Unix(0, dc.lastSeen.Load())
		if oldestKey == "" || last.Before(oldestTime) {
			oldestKey, oldestTime = k, last
		}
	}
	if oldestKey == "" {
		return nil
	}
	log.Debug("[UDP_DIRECT] session cap reached, evicting oldest idle", "key", oldestKey)
	evicted := s.directUDP[oldestKey]
	delete(s.directUDP, oldestKey)
	return evicted
}

// directUDPReadLoop 把来自直连远端的数据库报中继回客户端，直到 socket 失败或
// 读空闲截止时间在无数据的情况下触发。该截止时间与清理循环用于回收空闲会话的
// udpIdleTimeout 相同（用户配置超时的 2 倍），镜像服务端 UDP 处理器——它同样以
// 2 倍超时的空闲截止时间读取。退出时会关闭 socket 并从 map 中移除会话，但仅在
// 条目仍指向本会话时——绝不会移除指向替换它的新会话的条目。
func (s *Socks5Server) directUDPReadLoop(srv *socks5.Server, clientAddr *net.UDPAddr, dst, key string, dc *directUDPConn) {
	rc := dc.conn
	defer func() {
		rc.Close() //nolint:errcheck
		s.udpMu.Lock()
		if cur, ok := s.directUDP[key]; ok && cur == dc {
			delete(s.directUDP, key)
		}
		s.udpMu.Unlock()
	}()
	buf := bytespool.Get(protocol.MaxUDPDataSize)
	defer bytespool.MustPut(buf)
	for {
		_ = rc.SetReadDeadline(time.Now().Add(s.udpIdleTimeout))
		n, err := rc.Read(buf)
		if err != nil {
			return
		}
		// 接收时也刷新空闲时间戳，与发送一致，镜像代理路径
		// （UDPExchange.Receive）：一个只持续接收而不再写入的流（一次查询带来
		// 一长串响应）在仍然活跃时不能被回收。
		dc.lastSeen.Store(time.Now().UnixNano())
		s.sendToClient(srv, clientAddr, buf[:n], dst)
	}
}

func (s *Socks5Server) proxyUDPRelay(srv *socks5.Server, clientAddr *net.UDPAddr, d *socks5.Datagram, dst string) error {
	key := clientAddr.String() + "_" + dst

	ue, created, err := s.getOrCreateUDPExchange(context.Background(), key, dst, d.Data)
	if err != nil {
		log.Error("[UDP_PROXY] open exchange", "dst", dst, "err", err)
		return err
	}
	if created {
		// 非 DNS 的 UDP 不能使用较短的读空闲超时：会话可能合法地长时间沉默
		// （例如纯上传流），因此它只保留默认 60 秒的双向空闲回收器。
		go s.receiveLoop(ue, srv, clientAddr, dst, key, 0)
		return nil // 第一个载荷已在握手中发送
	}

	if err := ue.Send(d.Data); err != nil {
		log.Error("[UDP_PROXY] send", "err", err)
		s.udpMu.Lock()
		delete(s.udpExch, key)
		s.udpMu.Unlock()
		ue.Close() //nolint:errcheck
		return err
	}
	return nil
}

func responseDNSMsg(conn *net.UDPConn, addr *net.UDPAddr, msg *dns.Msg, dst string) error {
	data, err := msg.Pack()
	if err != nil {
		return err
	}
	a, addrBytes, port, err := socks5.ParseAddress(dst)
	if err != nil {
		return err
	}
	if a == socks5.ATYPDomain {
		addrBytes = addrBytes[1:]
	}
	resp := socks5.NewDatagram(a, addrBytes, port, data)
	_, err = conn.WriteToUDP(resp.Bytes(), addr)
	return err
}

func responseBlockedDNSMsg(conn *net.UDPConn, addr *net.UDPAddr, msg *dns.Msg, dst string) error {
	blockedDNSReply(msg)
	return responseDNSMsg(conn, addr, msg, dst)
}

// blockedDNSReply 把 msg 原地改造成一个"按策略屏蔽"的应答：响应位置位、清空
// 答案/授权/附加区。Rcode 刻意保持请求的原值（通常为 NOERROR），与 UDP 路径
// 的历史语义一致——NOERROR + 空答案会被解析器按 NXDOMAIN 之外的负缓存处理，
// 换用 REFUSED 反而让部分 stub resolver 反复重试同一被屏蔽域名。
// UDP 与 TCP DNS 路径共用。
func blockedDNSReply(msg *dns.Msg) *dns.Msg {
	msg.Response = true
	msg.Answer = nil
	msg.Ns = nil
	msg.Extra = nil
	return msg
}
