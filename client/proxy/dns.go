package proxy

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	clientconfig "github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util"
)

// isDNSQueryMsg 报告 msg 是否为待拦截的 DNS 查询：任意 qtype、必须带 Question 且不是响应。
// UDP 与 TCP 必须共用同一判定，否则同一域名的 MX/TXT 查询会在两条路径上分叉。
func isDNSQueryMsg(msg *dns.Msg) bool {
	return msg != nil && len(msg.Question) > 0 && !msg.Response
}

// clampDNSEDNS0 把查询宣告的 EDNS0 尺寸钳到隧道 UDP 数据报预算内，否则上游会发出超过服务端
// 读缓冲的应答。返回 false 表示无需重新打包。
func clampDNSEDNS0(msg *dns.Msg) bool {
	opt := msg.IsEdns0()
	if opt == nil || opt.UDPSize() <= protocol.MaxUDPDataSize {
		return false
	}
	opt.SetUDPSize(uint16(protocol.MaxUDPDataSize))
	return true
}

type dnsOptions struct {
	Router       *router.Router
	Cache        *easydns.Cache
	Pool         *udpPool
	Dial         func(ctx context.Context, network, addr string) (net.Conn, error)
	ServerDomain string
	// Timeouts 是归一化过的派生超时：DNSResp 是一次直连解析的共享预算兼代理交换的读空闲，
	// UDPIdle 兼作 TCP DNS 逐条查询之间的读空闲。
	Timeouts config.Timeouts
}

// dnsInterceptor 把一条查询分流到 Block / 缓存 / 直连 / 隧道代理四路，UDP 与 TCP 共用 plan。
type dnsInterceptor struct {
	router       *router.Router
	cache        *easydns.Cache
	pool         *udpPool
	dial         func(ctx context.Context, network, addr string) (net.Conn, error)
	serverDomain string
	respTimeout  time.Duration
	queryIdle    time.Duration
}

func newDNSInterceptor(opts dnsOptions) *dnsInterceptor {
	timeouts := opts.Timeouts.Normalize()
	return &dnsInterceptor{
		router:       opts.Router,
		cache:        opts.Cache,
		pool:         opts.Pool,
		dial:         opts.Dial,
		serverDomain: opts.ServerDomain,
		respTimeout:  timeouts.DNSResp,
		queryIdle:    timeouts.UDPIdle,
	}
}

func (d *dnsInterceptor) isServerDomain(domain string) bool {
	return d.serverDomain != "" && strings.EqualFold(domain, d.serverDomain)
}

type dnsAction uint8

const (
	dnsActionBlock dnsAction = iota
	dnsActionCacheHit
	dnsActionDirect
	dnsActionProxy
)

type dnsPlan struct {
	action dnsAction
	direct bool
	cached *dns.Msg
	domain string
	qtype  string
}

// plan 判定一条查询的分流动作，缓存命中的应答已改写为本条查询的 Id，AAAA 剥离也在此完成。
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

	// 服务器自身的域名绝不走代理：打开隧道需要再次解析它，会形成循环依赖。回退到直连
	// （绑定物理接口，绕过 TUN）。
	isServerDomain := d.isServerDomain(plan.domain)
	if isServerDomain {
		log.Info("[DNS_SERVER_DOMAIN] direct", "domain", plan.domain, "qtype", plan.qtype)
	}
	plan.direct = isServerDomain || rule == router.HostRuleDirect

	if cached := d.cache.Get(q.Name, plan.qtype, plan.direct); cached != nil {
		log.Debug("[DNS_CACHE] hit", "domain", plan.domain, "qtype", plan.qtype, "direct", plan.direct)
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

// resolveDirectDNS 不经隧道解析 msg：优先用客户端请求的解析器，否则内置公共 DNS 加系统 DNS
// 兜底。采用 reqServer 是不让发往内网解析器的查询被转投公共 DNS。
func (d *dnsInterceptor) resolveDirectDNS(msg *dns.Msg, domain, reqServer string) (*dns.Msg, error) {
	try := func(servers []string) (*dns.Msg, error) {
		return d.exchangeDirectDNSFromList(msg, servers)
	}

	var resp *dns.Msg
	var err error
	if d.usableDirectDNSServer(reqServer) {
		resp, err = d.exchangeDirectDNSFromList(msg, append([]string{reqServer}, clientconfig.DirectDNSServers...))
	} else {
		// 兜底列表必须是过滤后的可用上游：QueryWithBuiltinFirst 依据它是否为空决定要不要
		// 熔断内置服务器。
		fallback := func() []string { return d.filterDNSUpstreams(easydns.SystemDNSServers()) }
		resp, err = easydns.QueryWithBuiltinFirst(clientconfig.DirectDNSServers, fallback, try)
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

// usableDirectDNSServer 报告 addr 是否可作为直连解析目标；回环地址允许，那可能正是客户端配置
// 的本地解析器。
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

// filterDNSUpstreams 丢弃 ipv6_rule=disable 下永远拨不通的 IPv6 上游。构建兜底列表与真正发起
// 交换共用它，"是否存在兜底"才是同一份列表。
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

// exchangeDirectDNSFromList 用给定服务器并发交换 msg，取首个成功结果；内置优先的回退由调用方
// 施加。
func (d *dnsInterceptor) exchangeDirectDNSFromList(msg *dns.Msg, servers []string) (*dns.Msg, error) {
	candidates := d.filterDNSUpstreams(servers)
	if len(candidates) == 0 {
		return nil, errors.New("no dns server available")
	}

	// 去重：TUN 的系统 DNS 取自内置池，直连分支又把它前置到同一个池上。
	candidates = dedupeDNSUpstreams(candidates)

	// 并发查询每个上游：串行时一个卡住的上游会把每个数据报的处理 goroutine 阻塞到超时。
	ctx, cancel := context.WithTimeout(context.Background(), d.respTimeout)
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

	// ctx 取消（首个上游已成功）时立即关闭 conn，ReadMsg 不会一直等到 deadline。
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	_ = conn.SetDeadline(time.Now().Add(d.respTimeout))
	dnsConn := &dns.Conn{Conn: conn, UDPSize: 8192}
	if err := dnsConn.WriteMsg(msg); err != nil {
		return nil, directDNSError(ctx, err)
	}
	resp, err := dnsConn.ReadMsg()
	if err != nil {
		return nil, directDNSError(ctx, err)
	}
	// 部分家用路由器把 OPT 放进 ANSWER 段，真正的 A/AAAA 被挤到 ADDITIONAL。不规范化就写进
	// 缓存，后续几小时的查询都会回放这条坏应答。
	easydns.NormalizeEDNS0Answer(resp)
	return resp, nil
}

// ctx 取消是并发查询的预期结果，返回 ctx.Err() 让调用方与上游故障区分开。
func directDNSError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

// blockedDNSReply 把 msg 原地改造成屏蔽应答。Rcode 刻意保持原值：换成 REFUSED 会让部分 stub
// resolver 反复重试同一被屏蔽域名。
func blockedDNSReply(msg *dns.Msg) *dns.Msg {
	msg.Response = true
	msg.Answer = nil
	msg.Ns = nil
	msg.Extra = nil
	return msg
}
