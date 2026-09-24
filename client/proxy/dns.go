package proxy

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
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

// dnsOptions 是构造 dnsInterceptor 所需的全部依赖。Dial 以函数值注入（前端用
// 晚绑定闭包传入自己的拨号函数），因此拦截器不依赖 Socks5Server 类型。
type dnsOptions struct {
	Router *router.Router
	Cache  *easydns.Cache
	// Pool 提供经隧道的 UDP 交换（代理分支）与交换失效回收。
	Pool *udpPool
	// Dial 打开直连 UDP socket（直连解析）。
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// ServerDomain 是代理服务器自身的主机名（字面 IP 时为 ""）。
	ServerDomain string
	// DialTimeout 是一次直连解析（并发竞争多个上游）的共享预算。
	DialTimeout time.Duration
	// RespTimeout 限制代理 DNS 交换在没有任何服务器响应的情况下可保持多久
	// （读空闲超时）；0 表示禁用该机制。它存在的原因是：当客户端不断重试查询
	// （每次 Send 都会刷新 lastSeen）而上游 DNS 服务器一直沉默时，默认的空闲
	// 回收器永远不会触发。TCP DNS 的同步等待也用它。
	RespTimeout time.Duration
	// QueryIdle 是 TCP DNS 拦截逐条查询之间的读空闲超时；0 使用默认值。
	QueryIdle time.Duration
}

// dnsInterceptor 承担本地代理的 DNS 拦截：它把一条查询分流到 Block / 缓存 /
// 直连解析 / 经隧道代理四条路径，并把结果写入 easydns.Cache、按自定义域名规则
// 学习答案。
//
// UDP 与 TCP 两个前端共用同一个判定（plan）：前端只负责各自的报文封帧与
// （UDP 的）SOCKS5 数据报组帧，拦截器完全不接触 socks5.Server。
type dnsInterceptor struct {
	router       *router.Router
	cache        *easydns.Cache
	pool         *udpPool
	dial         func(ctx context.Context, network, addr string) (net.Conn, error)
	serverDomain string
	dialTimeout  time.Duration
	respTimeout  time.Duration
	queryIdle    time.Duration
}

// defaultTCPDNSIdleTimeout 是未提供 QueryIdle 时逐条 TCP DNS 查询之间的间隔。
const defaultTCPDNSIdleTimeout = 30 * time.Second

func newDNSInterceptor(opts dnsOptions) *dnsInterceptor {
	queryIdle := opts.QueryIdle
	if queryIdle <= 0 {
		queryIdle = defaultTCPDNSIdleTimeout
	}
	return &dnsInterceptor{
		router:       opts.Router,
		cache:        opts.Cache,
		pool:         opts.Pool,
		dial:         opts.Dial,
		serverDomain: opts.ServerDomain,
		dialTimeout:  opts.DialTimeout,
		respTimeout:  opts.RespTimeout,
		queryIdle:    queryIdle,
	}
}

// isServerDomain 报告给定域名是否是代理服务器自身的主机名。针对它的 DNS 查询
// 绝不能走代理路径：解析服务器域名需要打开隧道流，而打开隧道流又需要拨号到
// 服务器域名——这是一个会死锁的循环依赖（尤其是在系统休眠/唤醒后缓存条目可能
// 已过期时）。
func (d *dnsInterceptor) isServerDomain(domain string) bool {
	return d.serverDomain != "" && strings.EqualFold(domain, d.serverDomain)
}

// dnsAction 是一条查询分流后的动作。
type dnsAction uint8

const (
	dnsActionBlock dnsAction = iota
	dnsActionCacheHit
	dnsActionDirect
	dnsActionProxy
)

// dnsPlan 是一次查询的分流结果：动作、是否走直连缓存、命中的缓存应答，
// 以及日志用的域名与 qtype。
type dnsPlan struct {
	action dnsAction
	direct bool
	cached *dns.Msg
	domain string
	qtype  string
}

// plan 判定一条查询的分流动作。UDP 与 TCP 两条拦截路径共用它，使同一域名的
// 查询不会因为走的协议不同而出现不同的 Block/Direct/Proxy 结果；两条路径原本
// 逐行重复的这段逻辑（MatchHostRule → Block → 服务器域名 → 缓存 → 直连/代理）
// 由此收敛到一处。
//
// 缓存命中的应答已经改写为本条查询的 Id；AAA 剥离也在此完成。
func (d *dnsInterceptor) plan(msg *dns.Msg) dnsPlan {
	q := msg.Question[0]
	plan := dnsPlan{
		domain: strings.TrimSuffix(q.Name, "."),
		qtype:  dns.TypeToString[q.Qtype],
	}

	rule := d.router.MatchHostRule(plan.domain)
	if rule == router.HostRuleBlock {
		plan.action = dnsActionBlock
		return plan
	}

	// 对代理服务器自身的域名绝不走代理路径：打开隧道来应答查询会需要再次解析
	// 服务器域名，形成循环依赖。回退到直连路径（绑定到物理接口，绕过 TUN）。
	isServerDomain := d.isServerDomain(plan.domain)
	if isServerDomain {
		log.Info("[DNS_SERVER_DOMAIN] direct", "domain", plan.domain, "qtype", plan.qtype)
	}
	plan.direct = isServerDomain || rule == router.HostRuleDirect

	if cached := d.cache.Get(q.Name, plan.qtype, plan.direct); cached != nil {
		log.Info("[DNS_CACHE] hit", "domain", plan.domain, "qtype", plan.qtype, "direct", plan.direct)
		if d.router.ShouldIPV6Disable() && q.Qtype == dns.TypeAAAA {
			cached.Answer = nil
		}
		cached.Id = msg.Id
		plan.action = dnsActionCacheHit
		plan.cached = cached
		return plan
	}

	if plan.direct {
		plan.action = dnsActionDirect
		return plan
	}
	plan.action = dnsActionProxy
	return plan
}

// learnDNSAnswers 依据自定义直连/代理域名规则，从应答中学习 A/AAAA/CNAME，
// 供后续连接按 IP 或域名路由。UDP 与 TCP DNS 路径共用。
func (d *dnsInterceptor) learnDNSAnswers(msg *dns.Msg, domain string, isDirect bool) {
	if msg == nil {
		return
	}
	if isDirect {
		if !d.router.IsCustomDirectDomain(domain) {
			return
		}
		for _, ans := range msg.Answer {
			switch a := ans.(type) {
			case *dns.A:
				d.router.AddDirectIP(a.A.String())
			case *dns.AAAA:
				d.router.AddDirectIP(a.AAAA.String())
			case *dns.CNAME:
				d.router.AddDirectDomain(strings.TrimSuffix(a.Target, "."))
			}
		}
		return
	}
	if !d.router.IsCustomProxyDomain(domain) {
		return
	}
	util.ForEachDNSAnswer(msg, func(kind, value string) {
		if kind == "CNAME" {
			d.router.AddProxyDomain(value)
			return
		}
		d.router.AddProxyIP(value)
	})
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
func (d *dnsInterceptor) resolveDirectDNS(msg *dns.Msg, domain, reqServer string) (*dns.Msg, error) {
	try := func(servers []string) (*dns.Msg, error) {
		return d.exchangeDirectDNSFromList(msg, servers)
	}

	var resp *dns.Msg
	var err error
	if d.usableDirectDNSServer(reqServer) {
		resp, err = d.exchangeDirectDNSFromList(msg, append([]string{reqServer}, config.DirectDNSServers...))
	} else {
		// 兜底列表必须是过滤后的可用上游：QueryWithBuiltinFirst 依据它是否为
		// 空来决定要不要熔断内置服务器（见 easydns.QueryWithBuiltinFirst）。
		fallback := d.filterDNSUpstreams(easydns.SystemDNSServers())
		resp, err = easydns.QueryWithBuiltinFirst(config.DirectDNSServers, fallback, try)
	}
	if err != nil {
		return nil, err
	}
	if d.router.ShouldIPV6Disable() && msg.Question[0].Qtype == dns.TypeAAAA {
		resp.Answer = nil
	}
	_ = d.cache.Set(resp, true)
	d.learnDNSAnswers(resp, domain, true)
	return resp, nil
}

// usableDirectDNSServer 报告 addr 是否可作为直连解析的目标：必须是可拨号的
// 单播地址。未指定（0.0.0.0/::）与多播/广播地址永远不可用；ipv6_rule=disable
// 时 IPv6 上游也要忽略（exchangeDirectDNSFromList 同样会过滤，这里只是提前
// 让出内置兜底路径）。回环地址是允许的：那可能正是客户端配置的本地解析器
// （本机 DNS 转发服务器），拨过去仍能拿到应答，只是多一跳。
func (d *dnsInterceptor) usableDirectDNSServer(addr string) bool {
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
	if d.router.ShouldIPV6Disable() && util.IsIPV6(host) {
		return false
	}
	return true
}

// filterDNSUpstreams 丢弃当前规则下无法拨通的上游：ipv6_rule=disable 时
// IPv6 地址永远拨不通。它同时被兜底列表的构建（resolveDirectDNS）与实际交换
// （exchangeDirectDNSFromList）使用，使"是否存在可用兜底"与"真正会被尝试的
// 上游"是同一份列表。
func (d *dnsInterceptor) filterDNSUpstreams(servers []string) []string {
	var candidates []string
	for _, addr := range servers {
		if d.router.ShouldIPV6Disable() && util.IsIPV6Addr(addr) {
			continue
		}
		candidates = append(candidates, addr)
	}
	return candidates
}

// exchangeDirectDNSFromList 依次用给定的 DNS 服务器交换 msg。内置优先的回退
// （包括熔断器冷却时间）由调用方通过 easydns.QueryWithBuiltinFirst 施加。
func (d *dnsInterceptor) exchangeDirectDNSFromList(msg *dns.Msg, servers []string) (*dns.Msg, error) {
	candidates := d.filterDNSUpstreams(servers)
	if len(candidates) == 0 {
		return nil, errors.New("no dns server available")
	}

	// 去重：TUN 的系统 DNS 现在取自内置池（见 easydns.PreferredSystemDNS），
	// 直连分支把它作为 reqServer 前置到同一个池上，候选里会出现同一台服务器
	// 两次。并发竞争取首个成功结果，重复候选没有任何冗余收益，只会多拨一次。
	candidates = dedupeDNSUpstreams(candidates)

	// 并发查询每个上游并取第一个成功结果。串行扫描时，一个卡住的上游会把查询
	// 拖到单服务器超时上限，而每个数据报的处理 goroutine 都会阻塞在整个等待
	// 期间——DNS 故障时 goroutine 就会越积越多。整个查询共享一个超时预算。
	ctx, cancel := context.WithTimeout(context.Background(), d.dialTimeout)
	defer cancel()

	type result struct {
		resp *dns.Msg
		err  error
	}
	ch := make(chan result, len(candidates))
	for _, addr := range candidates {
		go func(addr string) {
			resp, err := d.exchangeDirectDNS(ctx, msg, addr)
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

// dedupeDNSUpstreams 原地去重上游列表，保持首次出现的顺序。TUN 的系统 DNS
// 取自内置池，会被前置到同一个池上做并发竞争，不去重就会对同一台服务器
// 重复拨号（重复候选在"首个成功即返回"的竞争里没有任何收益）。
func dedupeDNSUpstreams(servers []string) []string {
	deduped := servers[:0]
	for _, addr := range servers {
		if slices.Contains(deduped, addr) {
			continue
		}
		deduped = append(deduped, addr)
	}
	return deduped
}

func (d *dnsInterceptor) exchangeDirectDNS(ctx context.Context, msg *dns.Msg, addr string) (*dns.Msg, error) {
	conn, err := d.dial(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck

	_ = conn.SetDeadline(time.Now().Add(d.dialTimeout))
	dnsConn := &dns.Conn{Conn: conn, UDPSize: 8192}
	if err := dnsConn.WriteMsg(msg); err != nil {
		return nil, err
	}
	return dnsConn.ReadMsg()
}

// blockedDNSReply 把 msg 原地改造成一个"按策略屏蔽"的应答：响应位置位、清空
// 答案/授权/附加区。Rcode 刻意保持请求的原值（通常为 NOERROR），与 UDP 路径的
// 历史语义一致——NOERROR + 空答案会被解析器按 NXDOMAIN 之外的负缓存处理，
// 换用 REFUSED 反而让部分 stub resolver 反复重试同一被屏蔽域名。
// UDP 与 TCP DNS 路径共用。
func blockedDNSReply(msg *dns.Msg) *dns.Msg {
	msg.Response = true
	msg.Answer = nil
	msg.Ns = nil
	msg.Extra = nil
	return msg
}
