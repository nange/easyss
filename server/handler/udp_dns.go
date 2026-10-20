package handler

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/util"
)

// 指向 53 端口的会话不在建立时拨号：出站路由由 QNAME 决定。

// dnsPort 是触发"按查询域名路由"的端口。
const dnsPort = "53"

// isDNSPort 解析失败时按"不是 DNS"处理：只有明确的目标才值得为它推迟拨号。
func isDNSPort(target string) bool {
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	return port == dnsPort
}

type dnsRoute uint8

const (
	dnsRouteDirect dnsRoute = iota
	dnsRouteNextProxy
)

func (r dnsRoute) viaNextProxy() bool { return r == dnsRouteNextProxy }

// 判定与拨号必须同源：拆成两处就可能出现"判定说走代理、拨号却直连"。
type dnsRouter interface {
	routeForDomain(domain string) dnsRoute
	dialRoute(ctx context.Context, network, target, domain string, route dnsRoute) (net.Conn, string, error)
}

type udpRouteDialer struct {
	dialer    dialer
	nextProxy *nextproxy.NextProxy
}

// 配置了 next_proxy 但未开 enable_udp 时命中的目标一律直连，否则 DNS 查询会停在一条
// 不会成功的关联请求上。
func (d udpRouteDialer) dnsProxyAvailable() bool {
	return d.nextProxy != nil && d.nextProxy.EnableUDP()
}

func (d udpRouteDialer) routeForDomain(domain string) dnsRoute {
	// 复用 ShouldProxy，TCP、UDP 与 DNS 三条路径对"该不该走链式代理"才有一致语义。
	if d.dnsProxyAvailable() && domain != "" && d.nextProxy.ShouldProxy(domain) {
		return dnsRouteNextProxy
	}
	return dnsRouteDirect
}

// 直连路由必须走直连分支：交给代理分支会被当成"仅代理侧可解析的域名"先解析再转给上游，
// 多一跳，且解析到 LAN 地址时会得到一个毫无意义的 SSRF 拒绝。
func (d udpRouteDialer) dialRoute(ctx context.Context, network, target, domain string, route dnsRoute) (net.Conn, string, error) {
	if !route.viaNextProxy() {
		return d.dialer.dialVia(ctx, network, target, "", false)
	}
	return d.dialer.dialVia(ctx, network, target, domain, true)
}

// dnsState 只由主 goroutine 独占访问。
type dnsState struct {
	enabled bool
	router  dnsRouter
	// routeSel 是最近一条查询要求的路由，当前连接的路由在 connRoute。
	routeSel dnsRoute
	// dialDomain 只用于拨号日志。
	dialDomain string
	// rebindFailedAt 是上一次重绑拨号失败的时刻。失败后下一帧必然再次 changed，没有冷却的话
	// next proxy 长时间不可用时每个命中查询都会在主循环里同步吃满一次 DialTimeout。
	rebindFailedAt time.Time

	// 应答学习门控：DNS 会话每条查询都能判定，非 DNS 会话只在第一个客户端帧上判定一次。
	checked   bool
	intercept bool
}

// dialRoute 只负责拨出新连接，不安装进会话：重绑才能先拨成功、再一次性换掉旧连接。
func (s *udpSession) dialRoute(ctx context.Context, domain string, route dnsRoute) (net.Conn, string, error) {
	if s.dns.router != nil {
		return s.dns.router.dialRoute(ctx, "udp", s.target, domain, route)
	}
	return s.dial.dialVia(ctx, "udp", s.target, "", route.viaNextProxy())
}

// openUpstream 只在会话还没有连接时调用。
func (s *udpSession) openUpstream(ctx context.Context, domain string, route dnsRoute) error {
	conn, remote, err := s.dialRoute(ctx, domain, route)
	if err != nil {
		return err
	}
	s.installUpstream(conn, remote, route, s.readerRunning)
	logUpstreamConnected(s.target, remote, route)
	return nil
}

// 顺序是硬约束：先拨通新连接，成功后才换掉并关闭旧连接；拨号失败时旧连接与旧路由原样
// 保留，拨号期间旧连接仍在工作。旧连接上一问一答中途的查询由客户端自己重试。
func (s *udpSession) rebindRoute(domain string, route dnsRoute) {
	conn, remote, err := s.dialRoute(s.ctx, domain, route)
	if err != nil {
		s.dns.rebindFailedAt = time.Now()
		log.Warn("[UDP_DNS] rebind upstream failed, keeping the current route",
			"target", s.target,
			"want_via_next_proxy", route.viaNextProxy(),
			"retry_after", rebindCooldown.String(),
			"err", err)
		return
	}
	s.dns.rebindFailedAt = time.Time{}

	old := s.installUpstream(conn, remote, route, true)
	logUpstreamConnected(s.target, remote, route)
	if old != nil {
		// 旧连接的 reader 退出时会看到 s.upstream() 已不是自己，不会把这次关闭当成故障。
		old.Close() //nolint:errcheck
	}
}

// 首条连接与重绑两条安装路径共用它，日志字段只有一份定义。
func logUpstreamConnected(target, remote string, route dnsRoute) {
	log.Info("[UDP] upstream connected", "target", target, "remote", remote,
		"via_next_proxy", route.viaNextProxy())
}

// observeDNSFrame 在写入目标之前调用，返回时"该往哪条连接写"已经确定。
func (s *udpSession) observeDNSFrame(payload []byte) {
	if s.dns.enabled {
		s.noteDNSQuery(payload)
		return
	}
	// 一个会话只承载一次 DNS 查询的开端，后续数据报（QUIC 等）不该再被解析。
	if s.dns.checked {
		return
	}
	s.dns.checked = true
	domain, ok := dnsQueryDomain(payload)
	if !ok {
		return
	}
	s.dns.intercept = true
	log.Info("[UDP_DNS]", "domain", domain, "target", s.target,
		"via_next_proxy", s.targetRoute().viaNextProxy())
}

// targetRoute 与 dialTarget 用同一个 shouldProxy 谓词，日志才与"连接实际怎么拨的"一致。
func (s *udpSession) targetRoute() dnsRoute {
	if s.nextProxy != nil && s.nextProxy.EnableUDP() && s.nextProxy.ShouldProxy(s.target) {
		return dnsRouteNextProxy
	}
	return dnsRouteDirect
}

func (s *udpSession) noteDNSQuery(payload []byte) {
	domain, ok := dnsQueryDomain(payload)
	if !ok {
		return
	}
	s.dns.intercept = true

	route := dnsRouteDirect
	if s.dns.router != nil {
		route = s.dns.router.routeForDomain(domain)
	}
	s.dns.routeSel = route
	s.dns.dialDomain = domain

	// 判据必须是当前连接的路由而不是上一条查询：只比较前后两条查询会漏掉"首帧畸形 →
	// 直连兜底 → 首条真实查询"，让命中代理的查询被写进直连连接。
	connRoute, hasRoute := s.upstreamRoute()
	changed := hasRoute && connRoute != route
	if changed {
		if s.rebindCoolingDown() {
			s.logDNSRoute(domain, route, changed)
			return
		}
		s.rebindRoute(domain, route)
	}
	s.logDNSRoute(domain, route, changed)
}

// rebindCooldown 与 DialTimeout 的量级匹配（3~15s）：太短则每个查询都重新吃满一次拨号超时，
// 太长则 next proxy 恢复后迟迟切不回去。
const rebindCooldown = 10 * time.Second

// 只由主 goroutine 调用，rebindFailedAt 因此不需要额外同步。
func (s *udpSession) rebindCoolingDown() bool {
	return !s.dns.rebindFailedAt.IsZero() &&
		time.Since(s.dns.rebindFailedAt) < rebindCooldown
}

// via_next_proxy 读当前连接的路由而不是判定结果：重绑失败时旧连接被保留，两者不一致时另带
// route_pending=true。只有决定出站路径的查询记 Info，全记会让日志随查询数增长。
func (s *udpSession) logDNSRoute(domain string, want dnsRoute, changed bool) {
	actual, hasConn := s.upstreamRoute()
	viaNextProxy := want.viaNextProxy()
	if hasConn {
		viaNextProxy = actual.viaNextProxy()
	}
	attrs := []any{
		"domain", domain,
		"target", s.target,
		"via_next_proxy", viaNextProxy,
	}
	if changed && hasConn && actual != want {
		attrs = append(attrs, "route_changed", true, "route_pending", true)
		log.Info("[UDP_DNS]", attrs...)
		return
	}
	if changed {
		attrs = append(attrs, "route_changed", true)
		log.Info("[UDP_DNS]", attrs...)
		return
	}
	log.Debug("[UDP_DNS]", attrs...)
}

// dnsQueryDomain 不是查询（解析失败、是应答、没有 Question）时 ok 为 false。
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

// 只由主 goroutine 调用且调用点已用学习状态门控，普通中继流量（QUIC 等）不会被解析，
// `*dns.Msg` 也不会跨 goroutine 传递。
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

// learnFromDNS 把自定义域名的 CNAME 目标与解析出的 IP 喂给 next proxy 的动态路由表。
// 调用点是每个数据报都经过的热路径，未配置 nextProxy 或从未观察到 DNS 查询时直接返回。
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
