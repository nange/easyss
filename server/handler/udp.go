package handler

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/util/bytespool"
)

const udpBufSize = protocol.MaxUDPDataSize

// dnsPort 是触发"按查询域名路由"的端口。指向该端口的 UDP 会话承载的是 DNS
// 查询，因此它的出站目标要等读出 QNAME 之后才能决定（见 udpHandler.Handle）。
const dnsPort = "53"

type udpHandler struct {
	idleTimeout time.Duration
	dialTimeout time.Duration
	// nextProxy 在这里单独保存（而不仅存在于 dial 内部），因为只有 UDP
	// 会在数据报流上用它进行 DNS 应答学习，与当前目标是否经由它路由无关。
	nextProxy *nextproxy.NextProxy
	dial      dialer
	// route 把"这条 DNS 查询该走直连还是下一级代理"的判定与真正的拨号绑在
	// 一起（见 dnsRouter）。nextProxy 为 nil 时它也是 nil，所有查询直接出网。
	route dnsRouter
}

// newUDPHandler 用给定的空闲超时和基础超时创建 udpHandler。
// 与 newTCPHandler 一样，拨号超时通过 config.DialTimeout 派生
// （base/3，限制在 [3s, 15s]），而不是复用长得多的空闲超时。
func newUDPHandler(idleTimeout, timeout time.Duration, np *nextproxy.NextProxy) *udpHandler {
	if idleTimeout <= 0 {
		idleTimeout = config.DefaultUDPIdleTimeout
	}
	if timeout <= 0 {
		timeout = time.Duration(config.DefaultTimeout) * time.Second
	}
	dialTimeout := config.DialTimeout(timeout)
	directDialer := outboundDialer(dialTimeout, 0)
	h := &udpHandler{idleTimeout: idleTimeout, dialTimeout: dialTimeout, nextProxy: np}
	h.dial = dialer{
		nextProxy: np,
		shouldProxy: func(target string) bool {
			return np != nil && np.EnableUDP() && np.ShouldProxy(target)
		},
		direct: func(ctx context.Context, network, target string) (net.Conn, error) {
			return dialOutbound(ctx, directDialer, network, target)
		},
	}
	// 接口赋值只在 np 非 nil 时进行：把 (*nextproxy.NextProxy)(nil) 塞进接口
	// 会让 h.route != nil 成立，而它内部的方法都带 nil 接收者检查——那会掩盖
	// "未配置下一级代理"与"配置了但没命中"的区别。
	if np != nil {
		h.route = udpRouteDialer{dialer: h.dial, nextProxy: np}
	}
	return h
}

// dnsRoute 是一条 DNS 查询的出站路径。
type dnsRoute uint8

const (
	// dnsRouteDirect 是直接向查询目标（客户端配置的解析器，通常是 8.8.8.8:53）
	// 发出查询。
	dnsRouteDirect dnsRoute = iota
	// dnsRouteNextProxy 是把查询交给下一级 SOCKS5 代理去解析。
	dnsRouteNextProxy
)

func (r dnsRoute) viaNextProxy() bool { return r == dnsRouteNextProxy }

// dnsRouter 是 DNS 查询的出站路由：判定用域名（只有它才知道这条查询该不该走
// 下一级代理），拨号用会话目标。两者必须同源，否则"判定说走代理、拨号却直连"
// 会成为可能——因此拨号也由它提供，会话只拿结果，不再持有第二份 dialer。
type dnsRouter interface {
	routeForDomain(domain string) dnsRoute
	dialRoute(ctx context.Context, network, target, domain string, route dnsRoute) (net.Conn, string, error)
}

// udpRouteDialer 是 serving 环境的 dnsRouter：路由判定读 nextProxy 的文件
// 配置（glob/regexp/精确域名/IP/CIDR），拨号复用共享的 dialer（含 SSRF
// 预检查与 next-proxy 的 SOCKS5 拨号）。
//
// 只有 UDP 走这条路径：DNS 查询的 QNAME 让"按域名路由"成为可能，而 TCP/ICMP
// 的拨号目标在握手阶段就已确定（见 tcp.go / icmp.go）。
type udpRouteDialer struct {
	dialer    dialer
	nextProxy *nextproxy.NextProxy
}

// dnsProxyAvailable 报告下一级代理是否具备承载 UDP 的能力。配置了 next_proxy
// 但未开 enable_udp 时，命中的 UDP 目标一律直连（见 README 的 next_proxy
// 一节）：此时 DNS 会退回直连解析，而不是让查询停在一个不会成功的关联请求上。
func (d udpRouteDialer) dnsProxyAvailable() bool {
	return d.nextProxy != nil && d.nextProxy.EnableUDP()
}

func (d udpRouteDialer) routeForDomain(domain string) dnsRoute {
	// 判定复用 ShouldProxy：它与下一级代理的 IP/CIDR/域名/通配符配置是同一份
	// 规则，因此"某个域名走链式代理"在 TCP、UDP 与 DNS 三条路径上语义一致。
	if d.dnsProxyAvailable() && domain != "" && d.nextProxy.ShouldProxy(domain) {
		return dnsRouteNextProxy
	}
	return dnsRouteDirect
}

func (d udpRouteDialer) dialRoute(ctx context.Context, network, target, domain string, route dnsRoute) (net.Conn, string, error) {
	return d.dialer.dialVia(ctx, network, target, domain, route.viaNextProxy())
}

// dnsLearnHint 是由主 goroutine 独占的学习状态：DNS 会话里每条查询都能直接
// 判定为查询（目标是 53 端口），非 DNS 会话则只在第一个客户端帧上判定一次
// （一个会话只承载一次 DNS 查询的开端）。此后的 DNS 应答才允许被学习。
type dnsLearnHint struct {
	// checked 表示"第一个客户端帧"的判定已经完成（只对非 DNS 会话有效）。
	checked bool
	// intercept 表示该会话确实发出过一次 DNS 查询。
	intercept bool
}

// Handle 在客户端流与目标之间中继 UDP 数据报，并以结构化结果返回已推送的
// 载荷字节数与远端地址（日志由 serveSession 的唯一出口记录）。整个会话由
// udpSession 承载：收尾只有 close 一个入口，退出原因只有 run 的返回值一个。
// cancelRead 在 handler 终止（空闲超时/错误/FIN）时被调用：
// 它会解除可能正阻塞在读取客户端请求体上的帧读取 goroutine，
// 从而在 ServeHTTP 返回后不会有 goroutine 残留。
func (h *udpHandler) Handle(ctx context.Context, dr *crypto.DecryptedReader, s2c shaper.Shaper, target string, cancelRead func()) streamResult {
	log.Debug("[UDP] handler starting", "target", target)

	// 目标是 53 端口时会话承载的是 DNS 查询，而"这条查询该直连还是走下一级
	// 代理"只能由 QNAME 说了算（见 udpRouteDialer）：因此这里不拨号，把它推迟
	// 到第一条查询到达时（dnsSession=true 的会话由 dnsRoute 驱动拨号）。
	// 其他目标维持原语义：会话建立时按目标决定路由，第一个数据报之前就已连上。
	dnsSession := isDNSPort(target)
	var (
		conn   net.Conn
		remote string
	)
	if !dnsSession {
		var err error
		conn, remote, err = h.dial.dialTarget(ctx, "udp", target)
		if err != nil {
			log.Error("[UDP] dial target failed", "target", target, "err", err)
			sendRST(s2c)
			return streamResult{Err: err}
		}
	}

	s := newUDPSession(udpSessionConfig{
		conn:        conn,
		remote:      remote,
		target:      target,
		dnsSession:  dnsSession,
		dr:          dr,
		s2c:         s2c,
		cancelRead:  cancelRead,
		idleTimeout: h.idleTimeout,
		dialTimeout: h.dialTimeout,
		nextProxy:   h.nextProxy,
		route:       h.route,
		dial:        h.dial,
	})
	result := s.run()
	if result.needsRST() {
		sendRST(s2c)
	}
	return result
}

// isDNSPort 报告目标是否是 53 端口（TCP/UDP 的 DNS）。解析失败时按"不是 DNS"
// 处理：只有明确的目标才值得为它推迟拨号。
func isDNSPort(target string) bool {
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	return port == dnsPort
}

// udpSession 承载一次 UDP 中继的全部状态。所有跨 goroutine 的协调都收敛在
// 这里：done 是唯一的关闭信号，close 是唯一的收尾入口（是否发 RST 由调用方
// 按结果决定），run 的返回值是唯一的退出原因。读取 goroutine 只经 resultCh
// 回传结果，不持有任何会被其他 goroutine 修改的状态。
type udpSession struct {
	// conn 是当前出站连接。DNS 会话会在查询路由变化时重绑它（见 rebindRoute），
	// 因此它由 mu 保护；其他会话在整个会话期间只写一次。
	conn   net.Conn
	remote string
	target string
	// dnsSession 表示目标是 DNS 端口：出站连接由查询域名决定，可以中途重绑。
	dnsSession bool

	dr          *crypto.DecryptedReader
	s2c         shaper.Shaper
	cancelRead  func()
	idleTimeout time.Duration
	dialTimeout time.Duration
	nextProxy   *nextproxy.NextProxy
	route       dnsRouter
	dial        dialer
	// routeSel 是当前查询选定的出站路由，只由 dnsSession 的会话写入：其他
	// 会话的路由由 dialTarget 按目标一次性决定，不经过这里。
	routeSel dnsRoute
	// routeSet 表示 routeSel 已经由一条 DNS 查询确定（DNS 会话的第一条查询）。
	routeSet bool
	// dialDomain 是最近一次触发路由判定的域名，只用于拨号日志（"是哪条查询
	// 让这条连接走下一级代理的"）。
	dialDomain string

	mu sync.Mutex

	// done 是唯一的关闭信号：close 关闭它，两个读取 goroutine 都在发送
	// 结果之前检查它。
	done chan struct{}
	// closed 让读取侧能区分"会话主动收尾"与"目标侧真实故障"：
	// 前者必然产生 read deadline exceeded / closed network connection，
	// 不能按故障记录。它由 closeOnce 关闭，因此只会关闭一次。
	closed    chan struct{}
	closeOnce sync.Once
	// readers 跟踪会话的读取 goroutine（目标侧与客户端帧侧）。close 会等它们
	// 退出后返回，因此"会话结束后没有读取 goroutine 残留"是收尾的一部分，而
	// 不是一个只能靠 sleep 观察的猜测。
	//
	// 目标侧在重绑时会为**新**连接再登记一个 goroutine：旧 goroutine 总是先因
	// 旧连接被关闭而退出，所以"Wait 与 Add 并发"永远不会发生。
	readers sync.WaitGroup
	// readerRunning 表示 run 已接管目标侧读取侧：此后的连接安装（DNS 会话的
	// 首条连接、以及每次重绑）都要顺带启动读取 goroutine，否则新连接会没人读。
	readerRunning bool
	// resultCh 携带目标侧读到的每个数据报。
	resultCh chan udpDatagram
	// dns 是完全由主 goroutine 私有的学习状态（读取侧只回传已解析的报文）。
	dns dnsLearnHint

	// transferred 是服务端到客户端方向已推送的载荷字节数。它只由主
	// goroutine 写入（读取侧经 resultCh 回传后累加），因此没有并发访问。
	transferred int64
}

// udpSessionConfig 是 udpSession 的构造参数。
type udpSessionConfig struct {
	conn        net.Conn
	remote      string
	target      string
	dnsSession  bool
	dr          *crypto.DecryptedReader
	s2c         shaper.Shaper
	cancelRead  func()
	idleTimeout time.Duration
	dialTimeout time.Duration
	nextProxy   *nextproxy.NextProxy
	route       dnsRouter
	dial        dialer
}

// newUDPSession 组装一个会话。所有跨 goroutine 的共享状态（关闭信号、结果
// 通道）在这里一次性创建，run 只驱动它们——因此 close 在 run 开始之前就是
// 可用的，测试不必与 run 竞争初始化。
func newUDPSession(cfg udpSessionConfig) *udpSession {
	return &udpSession{
		conn:        cfg.conn,
		remote:      cfg.remote,
		target:      cfg.target,
		dnsSession:  cfg.dnsSession,
		dr:          cfg.dr,
		s2c:         cfg.s2c,
		cancelRead:  cfg.cancelRead,
		idleTimeout: cfg.idleTimeout,
		dialTimeout: cfg.dialTimeout,
		nextProxy:   cfg.nextProxy,
		route:       cfg.route,
		dial:        cfg.dial,
		done:        make(chan struct{}),
		closed:      make(chan struct{}),
		resultCh:    make(chan udpDatagram, 1),
	}
}

// upstream 返回当前出站连接。写侧只在会话建立时（或 DNS 路由重绑时）改写它。
func (s *udpSession) upstream() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

// setUpstream 安装一条新的出站连接，并按需为它补上读取侧。返回值是写给日志的
// 远端地址。
//
// watch 为真表示"这次安装发生在 run 已经接管读取侧之后"，也就是 DNS 会话的
// 第一条连接（由主循环在处理第一个查询时安装）与之后每次重绑——两种情况下旧
// 连接的读取 goroutine 都已退出，因此必须补一个新的。非 DNS 会话建立连接时
// watch 为假：它的读取 goroutine 由 run 统一启动，重复登记会让同一条连接被读两次。
func (s *udpSession) setUpstream(conn net.Conn, remote string, watch bool) string {
	s.mu.Lock()
	s.conn = conn
	s.remote = remote
	addr := remote
	s.mu.Unlock()
	if watch {
		s.startUpstreamReader()
	}
	return addr
}

// closeUpstream 关闭并摘除当前出站连接；返回被摘除的连接（没有则 nil）。
func (s *udpSession) closeUpstream() net.Conn {
	s.mu.Lock()
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()
	if conn != nil {
		conn.Close() //nolint:errcheck
	}
	return conn
}

// udpDatagram 是读取 goroutine 回传给主 goroutine 的一个目标侧数据报。
// 它只携带原始载荷：DNS 解析由主 goroutine 按学习状态门控（见 maybeDNS），
// 读取侧因此不对普通中继流量（QUIC 等）做任何解析。
type udpDatagram struct {
	payload []byte
	err     error
}

// run 驱动整个 UDP 会话，返回唯一的退出结果。
func (s *udpSession) run() (out streamResult) {
	// 收尾只有这一处：无论从哪个分支退出（FIN/RST、目标 EOF、错误、空闲超时），
	// 都在这里关闭目标连接、解除读取侧的阻塞、等待读取 goroutine 退出。
	defer func() {
		s.close()
		s.mu.Lock()
		out.Remote = s.remote
		s.mu.Unlock()
		out.Bytes = s.transferred
	}()

	// 从这里起"安装连接"（DNS 会话的首条查询、或重绑）都必须由 setUpstream
	// 补上读取侧：DNS 会话在 run 开始时还没有连接，它的第一条连接正是由主循环
	// 在处理第一个查询时安装的。
	s.readerRunning = true
	if s.upstream() != nil {
		s.startUpstreamReader()
	}

	frameCh := make(chan udpFrameResult, 1)
	s.readers.Go(func() { s.readClientFrames(frameCh) })

	idle := time.NewTimer(s.idleTimeout)
	defer idle.Stop()

	// 空闲计时器是会话唯一的超时来源：任何客户端帧都会重置它，触发即结束。
	// 定时器只触发一次，且触发分支直接返回，因此收尾时不需要排空 timer.C。
	idleC := idle.C

	for {
		select {
		// done 让 close 成为真正可以从外部终止会话的入口：客户端与目标两侧
		// 都沉默时，这条分支是 run 唯一的退出路径（读取侧也因此被唤醒）。
		case <-s.done:
			return streamResult{}
		case res := <-s.resultCh:
			if res.err != nil {
				return streamResult{Err: res.err}
			}
			s.transferred += int64(len(res.payload))
			// 门控解析：只有确实发出过 DNS 查询的会话才尝试 Unpack 应答。
			// UDP 中继的主力是 QUIC 这类非 DNS 流量，对每个数据报做一次
			// Unpack 是纯粹的浪费（约 350ns/240B/4 allocs，随总吞吐线性放大）。
			if s.dns.intercept {
				s.learnFromDNS(res.payload)
			}
			// 用 NewFrameWithPayload 而非 NewFrameDATAGRAM：后者内部会 append
			// 复制一份载荷，而载荷已经由 readFromTarget 从读缓冲拷出来，第二次
			// 复制纯属多余（大报文时还会每次都产生一个绕过池的堆块）。
			// 所有权：PushFrame 在 bs.mu 下把载荷拷进整形器的明文缓冲后即返回，
			// 调用方仍拥有 res.payload，因此这里不需要复制。它的成立条件是
			// shaper 对 DATAGRAM 恒不归还载荷（putPayload 仅对 FrameCOVER 为真，
			// 见 shaper.appendFrameLocked）——若将来改成"归还任何池化载荷"，
			// 这里会立即变成跨流数据污染。
			if err := s.s2c.PushFrame(protocol.NewFrameWithPayload(protocol.FrameDATAGRAM, res.payload)); err != nil {
				return streamResult{Err: err}
			}
		case res := <-frameCh:
			if res.err != nil {
				return streamResult{Err: res.err}
			}
			alive, err := s.observeClientFrame(res.frame)
			if err != nil {
				return streamResult{Err: err}
			}
			if !alive {
				return streamResult{}
			}
			// 任何客户端帧都刷新空闲计时。
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(s.idleTimeout)
			idleC = idle.C
		case <-idleC:
			// 定时器只触发一次，且这是唯一的结束分支：直接返回，不与
			// 已经消费过的定时器事件再次竞争。
			return streamResult{TimedOut: true}
		}
	}
}

// observeClientFrame 处理一个客户端帧，返回 alive=false 表示流已终结
// （FIN/RST）——终止判定与帧处理因此只有一处，不再由调用方重复判断类型。
func (s *udpSession) observeClientFrame(f protocol.Frame) (alive bool, err error) {
	if f.Type != protocol.FrameDATAGRAM || len(f.Payload) == 0 {
		switch f.Type {
		case protocol.FrameFIN, protocol.FrameRST:
			return false, nil
		default:
			// PADDING/COVER 等填充帧不影响会话状态。
			return true, nil
		}
	}

	if s.dnsSession {
		// DNS 会话：每条查询的 QNAME 都可能改变出站路由（见 rebindRoute）。
		s.noteDNSQuery(f.Payload)
	} else if !s.dns.checked {
		// 非 DNS 会话只在第一个数据报上判定一次：一个会话只承载一次 DNS
		// 查询的开端，后续数据报（QUIC 等）不该再被解析。
		s.dns.checked = true
		if domain, ok := dnsQueryDomain(f.Payload); ok {
			s.dns.intercept = true
			// 非 DNS 会话的路由在建立连接时就已按目标定下；routeSel 为未设置
			// 的零值（直连），与 dialTarget 的判定一致。
			log.Info("[UDP_DNS]", "domain", domain, "target", s.target,
				"via_next_proxy", s.routeSel.viaNextProxy())
		}
	}

	conn, err := s.upstreamOrDial()
	if err != nil {
		return false, err
	}
	if _, err := conn.Write(f.Payload); err != nil {
		return false, err
	}
	return true, nil
}

// upstreamOrDial 返回当前出站连接；DNS 会话的第一条查询到这里才真正拨号
// （见 udpHandler.Handle）。连接掉线后再需要发送时会重拨一次，重拨失败即
// 结束会话——此时客户端会自行重试整条查询。
func (s *udpSession) upstreamOrDial() (net.Conn, error) {
	conn := s.upstream()
	if conn != nil {
		return conn, nil
	}
	if err := s.dialUpstream(context.Background(), s.dialDomain); err != nil {
		return nil, err
	}
	conn = s.upstream()
	if conn == nil {
		return nil, errors.New("udp upstream not established")
	}
	return conn, nil
}

// noteDNSQuery 在 DNS 会话里处理一条查询：学习门控、路由判定与路由变化后的
// 重绑。它是主 goroutine 私有的状态转换，与数据报的发送顺序一致。
func (s *udpSession) noteDNSQuery(payload []byte) {
	domain, ok := dnsQueryDomain(payload)
	if !ok {
		return
	}
	s.dns.intercept = true

	route := dnsRouteDirect
	if s.route != nil {
		route = s.route.routeForDomain(domain)
	}
	changed := s.routeSet && s.routeSel != route
	s.routeSel = route
	s.routeSet = true
	s.dialDomain = domain

	logDNSRoute(domain, s.target, route, changed)
	if changed {
		s.rebindRoute(domain)
	}
}

// logDNSRoute 输出一条 DNS 查询的路由判定。via_next_proxy 是这条查询**实际**
// 使用的出站路径，不再是"承载它的会话碰巧怎么拨的"：只有域名命中下一级代理
// 的规则、且 next_proxy.enable_udp 为真时它才为 true。changed 只在会话中途
// 换过路由时为真，避免同一会话里的重复查询刷屏。
func logDNSRoute(domain, target string, route dnsRoute, changed bool) {
	attrs := []any{"domain", domain, "target", target, "via_next_proxy", route.viaNextProxy()}
	if changed {
		attrs = append(attrs, "route_changed", true)
	}
	log.Info("[UDP_DNS]", attrs...)
}

// rebindRoute 按新的路由重建出站连接：先摘除并关闭旧连接（读取它的 goroutine
// 会因此返回并退出），再按新路由拨号并为其启动新的读取 goroutine。旧连接上
// 尚未回包的查询由客户端自己重试——DNS 客户端对超时查询的重试是标准行为。
func (s *udpSession) rebindRoute(domain string) {
	s.closeUpstream()
	if err := s.dialUpstream(context.Background(), domain); err != nil {
		log.Warn("[UDP_DNS] rebind upstream failed", "target", s.target,
			"via_next_proxy", s.routeSel.viaNextProxy(), "err", err)
	}
}

// dialUpstream 拨号出站连接，并按当前路由判定是否经由下一级代理。这是会话
// 里唯一建立出站连接的地方：建立（DNS 会话的第一条查询、非 DNS 会话的
// Handle）与重绑（rebindRoute）共用它，因此"判定—拨号—记录远端"只有一套。
func (s *udpSession) dialUpstream(ctx context.Context, domain string) error {
	var (
		conn         net.Conn
		remote       string
		viaNextProxy bool
		err          error
	)
	switch {
	case s.dnsSession && s.route != nil:
		if !s.routeSet {
			// 还没有解析出任何 DNS 查询（首帧不是合法查询，例如被填充帧隔开，
			// 或客户端发来了畸形报文）：按直连兜底，让这些数据报仍然能出去；
			// 真正的查询一到达就会按域名判定并按需重绑（noteDNSQuery）。
			conn, remote, err = s.dial.dialVia(ctx, "udp", s.target, "", false)
			break
		}
		viaNextProxy = s.routeSel.viaNextProxy()
		conn, remote, err = s.route.dialRoute(ctx, "udp", s.target, domain, s.routeSel)
	case s.dnsSession:
		// 未配置下一级代理：DNS 查询一律直连（route 为 nil）。
		conn, remote, err = s.dial.dialVia(ctx, "udp", s.target, "", false)
	default:
		viaNextProxy = s.nextProxy != nil && s.nextProxy.EnableUDP() && s.nextProxy.ShouldProxy(s.target)
		conn, remote, err = s.dial.dialVia(ctx, "udp", s.target, "", viaNextProxy)
	}
	if err != nil {
		return err
	}
	s.setUpstream(conn, remote, s.readerRunning)
	log.Info("[UDP] upstream connected", "target", s.target, "remote", remote,
		"via_next_proxy", viaNextProxy)
	return nil
}

// dnsQueryDomain 解出一次 DNS 查询的 QNAME；不是查询（解析失败、是应答、
// 没有 Question）时 ok 为 false。
func dnsQueryDomain(payload []byte) (string, bool) {
	msg := &dns.Msg{}
	if err := msg.Unpack(payload); err != nil {
		return "", false
	}
	if !util.IsDNSRequest(msg) {
		return "", false
	}
	return strings.TrimSuffix(msg.Question[0].Name, "."), true
}

// startUpstreamReader 为当前出站连接启动一个读取 goroutine。连接被重绑时旧
// goroutine 会因旧连接被关闭而自然结束，随后由这里为同一时刻安装上的新连接再
// 起一个——两者是严格串行的，因此 readers.WaitGroup 不会出现"Wait 与 Add 并发"
// 的用法（关闭路径只等待已经登记的 goroutine）。
func (s *udpSession) startUpstreamReader() {
	s.readers.Go(s.readFromTarget)
}

// readFromTarget 读取**一条**出站连接并把原始报文回传给主 goroutine；是否解析、
// 是否学习、是否推送都由主 goroutine 决定。它读取的连接在进入时固定（见下），
// 因此不需要在读取中途切换目标。
//
// 回传（含错误）都遵守 done：会话一旦收尾，读取侧必须能立即退出，而不是
// 卡在向一个已经没有接收者的通道发送上——close 会等待这个 goroutine。
func (s *udpSession) readFromTarget() {
	buf := bytespool.Get(udpBufSize)
	defer bytespool.MustPut(buf)

	// 连接在进入本 goroutine 时固定：路由重绑必然发生在客户端帧的处理过程中
	// （主 goroutine），而重绑会先把旧连接换掉并关闭——从这里取到的连接要么是
	// 重绑前的那条（随后被关闭，读取返回错误并按正常收尾），要么是重绑后的
	// 新连接（由 startUpstreamReader 再起的 goroutine 负责）。
	conn := s.upstream()
	if conn == nil {
		return
	}

	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.idleTimeout))
		n, err := conn.Read(buf)
		if err != nil {
			if conn != s.upstream() {
				// 这条连接已经被重绑替换：它的错误是拆连接的预期结果，不是目标
				// 故障，也不该拿去结束会话——新连接的读取 goroutine 已经接手。
				return
			}
			s.sendResult(udpDatagram{err: s.targetReadError(err)})
			return
		}
		payload := append([]byte(nil), buf[:n]...)
		if !s.sendResult(udpDatagram{payload: payload}) {
			return
		}
	}
}

// sendResult 把一条目标侧结果交给主 goroutine；done 关闭后放弃并返回 false。
func (s *udpSession) sendResult(d udpDatagram) bool {
	select {
	case s.resultCh <- d:
		return true
	case <-s.done:
		return false
	}
}

// targetReadError 归一化目标侧读取错误：读取截止时间与连接关闭都是会话
// 结束的正常路径（前者由空闲计时器或 close 触发），返回 io.EOF 让主
// goroutine 走正常收尾；只有在会话仍然存活时才是真实故障。
func (s *udpSession) targetReadError(err error) error {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
		return io.EOF
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return io.EOF
	}
	select {
	case <-s.closed:
		// 会话已关闭：这是主动拆连接的结果，不是目标故障。
		return io.EOF
	default:
	}
	log.Error("[UDP] read from target failed", "target", s.remote, "err", err)
	return err
}

// maybeDNS 解析一个疑似 DNS 应答；不是 DNS 应答时返回 nil。它只由主
// goroutine 调用，且调用点已用学习状态门控，因此普通中继流量（QUIC 等）
// 不会被解析，`*dns.Msg` 也不会跨 goroutine 传递。
func (s *udpSession) maybeDNS(payload []byte) *dns.Msg {
	if len(payload) == 0 {
		return nil
	}
	msg := &dns.Msg{}
	if err := msg.Unpack(payload); err != nil {
		return nil
	}
	if !util.IsDNSResponse(msg) {
		return nil
	}
	return msg
}

// learnFromDNS 用指向自定义域名的 DNS 应答喂给 next proxy 的动态路由表
// （CNAME 目标与解析出的 IP）。
//
// 它自带双门控，因为调用点（主循环的目标侧分支）是每个数据报都会经过的
// 热路径：nextProxy 未配置、或会话从未观察到 DNS 查询时直接返回，普通中继
// 流量（QUIC 等）因此不会被解析。intercept 是主 goroutine 私有状态，读取侧
// 不参与该判定。
func (s *udpSession) learnFromDNS(payload []byte) {
	if s.nextProxy == nil || !s.dns.intercept {
		return
	}
	msg := s.maybeDNS(payload)
	if msg == nil {
		return
	}
	domain := strings.TrimSuffix(msg.Question[0].Name, ".")
	if !s.nextProxy.IsCustomDomain(domain) {
		return
	}
	util.ForEachDNSAnswer(msg, func(kind, value string) {
		if kind == "CNAME" {
			s.nextProxy.AddDomain(value)
			return
		}
		s.nextProxy.AddIP(value)
	})
}

// udpFrameResult 是客户端帧读取 goroutine 回传的一个结果。
type udpFrameResult struct {
	frame protocol.Frame
	err   error
}

// readClientFrames 把客户端帧转发给主 goroutine，并在会话关闭后退出。
// 写入带缓冲的 frameCh 最多让它在退出前多阻塞一次发送，不可能泄漏。
func (s *udpSession) readClientFrames(frameCh chan<- udpFrameResult) {
	for {
		frame, err := s.dr.ReadFrame()
		select {
		case frameCh <- udpFrameResult{frame: frame, err: err}:
		case <-s.done:
			return
		}
		if err != nil {
			return
		}
	}
}

// close 是唯一的收尾入口：关闭客户端读取、把目标读取的截止时间提前到此刻
// （让阻塞中的读取 goroutine 立即返回，而不是等满一个空闲超时）、关闭连接
// 并停止空闲计时器。它还会等待两个读取 goroutine 真正退出后才返回，因此
// "会话结束后没有读取 goroutine 残留"是收尾的确定性结果。
// 可重复调用：先到者执行一次收尾，后到者等待其完成。它必须由驱动 run 的
// goroutine（或测试）调用，不能从被它等待的读取 goroutine 内部调用。
func (s *udpSession) close() {
	if s.done == nil {
		return
	}
	s.closeOnce.Do(func() {
		close(s.done)
		if s.cancelRead != nil {
			s.cancelRead()
		}
		// 把截止时间提前到此刻：读取侧阻塞在 conn.Read 上时，这是让它立即
		// 返回的唯一手段（只关连接也能唤醒，但先设截止时间对两种实现都成立）。
		if conn := s.upstream(); conn != nil {
			_ = conn.SetReadDeadline(time.Now())
		}
		s.closeUpstream()
		close(s.closed)
	})
	s.readers.Wait()
}
