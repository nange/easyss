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

// 本文件是 UDP 中继里的 DNS 部分：指向 53 端口的会话不在建立时拨号，而是读出
// QNAME 之后按查询域名决定出站路由（直连解析器，或交给下一级代理）。
//
// 它与 udp.go 的分工是：udp.go 只管"会话如何中继数据报"（帧循环、出站连接的
// 生命周期、收尾），本文件管"DNS 会话该往哪里拨、以及从应答里学到什么"。
// 两者的接口只有三处：udpHandler.Handle 用 isDNSPort 决定是否推迟拨号、
// udpSession.observeClientFrame 调 observeDNSFrame、udpSession.openUpstream 调
// dnsRouter.dialRoute。

// dnsPort 是触发"按查询域名路由"的端口。指向该端口的 UDP 会话承载的是 DNS
// 查询，因此它的出站目标要等读出 QNAME 之后才能决定（见 udpHandler.Handle）。
const dnsPort = "53"

// isDNSPort 报告目标是否是 53 端口（TCP/UDP 的 DNS）。解析失败时按"不是 DNS"
// 处理：只有明确的目标才值得为它推迟拨号。
func isDNSPort(target string) bool {
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	return port == dnsPort
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

// dialRoute 按路由拨号：只有代理路由走 dialVia 的代理分支，直连路由一律走
// 直连分支。把直连也交给代理分支会让目标被当作"仅代理侧可解析的域名"处理——
// 那会先解析再把它交给上游代理，对命中直连的域名既多一跳，也会在域名解析到
// LAN 地址时得到一个毫无意义的 SSRF 拒绝（目标本来就是服务端要直连解析器）。
func (d udpRouteDialer) dialRoute(ctx context.Context, network, target, domain string, route dnsRoute) (net.Conn, string, error) {
	if !route.viaNextProxy() {
		return d.dialer.dialVia(ctx, network, target, "", false)
	}
	return d.dialer.dialVia(ctx, network, target, domain, true)
}

// dnsState 是一个会话里与 DNS 相关的全部状态，由 udpSession.dns 持有（主
// goroutine 独占）。把路由判定、当前连接的路由、应答学习收在一处，使 udp.go
// 不需要知道任何 DNS 细节。
type dnsState struct {
	// enabled 表示目标是 DNS 端口：出站连接由查询域名决定，可以中途重绑。
	enabled bool
	// router 把"这条查询该走直连还是下一级代理"的判定与真正的拨号绑在一起
	// （见 dnsRouter）。nextProxy 为 nil 时它是 nil，所有查询直接出网。
	router dnsRouter
	// routeSel 是最近一条查询要求的路由。首帧不是合法查询时它仍是零值
	// （直连兜底），并与当前连接实际使用的路由一起被用来发现"要换路由"。
	//
	// 当前连接的路由（connRoute）不放在这里：它与 conn 必须同生共死，因此由
	// udpSession 在 mu 下与 conn 一起保存（见 udpSession.upstreamRoute）。
	// 首帧不是合法查询时（53 端口上的畸形流量）会话会按直连兜底先拨一条，
	// 此后第一条真实查询必须与**连接的路由**比较才能发现要换路由——只比较连续
	// 两条查询的 routeSel 会漏掉这一段。
	routeSel dnsRoute
	// dialDomain 是最近一次触发路由判定的域名，只用于拨号日志（"是哪条查询
	// 让这条连接走下一级代理的"）。
	dialDomain string
	// rebindFailedAt 是上一次重绑拨号失败的时刻（零值表示从未失败或之后已成功）。
	// 失败后 routeSel 已是新路由、connRoute 仍是旧路由，因此下一帧会再次
	// changed=true；若不加冷却，next proxy 长时间不可用时每个命中查询都会在主
	// 循环里同步吃满一次 DialTimeout（3~15s），DNS 会话会被拖死、日志也会刷屏。
	// 冷却窗口内直接复用旧连接，不再拨号。
	rebindFailedAt time.Time

	// 以下是应答学习状态：DNS 会话里每条查询都能直接判定为查询（目标是 53
	// 端口），非 DNS 会话则只在第一个客户端帧上判定一次（一个会话只承载一次
	// DNS 查询的开端）。此后的 DNS 应答才允许被学习。
	//
	// checked 表示"第一个客户端帧"的判定已经完成（只对非 DNS 会话有效）；
	// intercept 表示该会话确实发出过一次 DNS 查询。
	checked   bool
	intercept bool
}

// dialRoute 按给定路由建立一条新的出站连接（不安装进会话）。判定与拨号同源：
// 有 router 时全部交给它（直连路由走共享 dialer 的直连分支，见
// udpRouteDialer.dialRoute），没有它时（未配置下一级代理的会话、非 DNS 会话）
// 由调用方自己的拨号器按路由拨。
//
// 它只负责"拨"，安装与替换是 openUpstream / rebindRoute 的事：这样重绑可以
// 先把新连接拨出来，成功之后再一次性换掉旧连接（见 rebindRoute）。
func (s *udpSession) dialRoute(ctx context.Context, domain string, route dnsRoute) (net.Conn, string, error) {
	if s.dns.router != nil {
		return s.dns.router.dialRoute(ctx, "udp", s.target, domain, route)
	}
	return s.dial.dialVia(ctx, "udp", s.target, "", route.viaNextProxy())
}

// openUpstream 按路由建立并安装第一条出站连接。它只用于会话还没有连接时：
// 非 DNS 会话的 Handle、DNS 会话的第一条查询（见 upstreamOrDial）。
//
// 安装是"连接 + 路由"的一次原子替换（见 installUpstream），因此不会出现
// connRoute 指向旧路由而 conn 已经是新连接的中间态。
func (s *udpSession) openUpstream(ctx context.Context, domain string, route dnsRoute) error {
	conn, remote, err := s.dialRoute(ctx, domain, route)
	if err != nil {
		return err
	}
	s.installUpstream(conn, remote, route, s.readerRunning)
	logUpstreamConnected(s.target, remote, route)
	return nil
}

// rebindRoute 在查询要求的路由与当前连接的路由不一致时重绑出站连接。
//
// 顺序是硬约束：**先拨新连接，成功后才换掉并关闭旧连接**。这样：
//   - 拨号失败时旧连接与旧路由原样保留，后续查询继续走旧路径，而不是把一条
//     本来可用的会话拖垮（旧实现先关旧连接，失败后只能让同一帧的
//     upstreamOrDial 再拨一次，单条查询串行吃两次拨号超时）；
//   - 拨号期间旧连接仍在工作，不会出现"路由判定完成、新连接还没建立"的空窗；
//   - 每一帧最多拨一次：失败后 conn 非 nil，upstreamOrDial 不会再拨。
//
// 旧连接上尚未回包的查询由客户端自己重试——DNS 客户端对超时查询的重试是标准
// 行为。旧连接的读取 goroutine 会因旧连接被关闭而退出；新连接的读取 goroutine
// 由 installUpstream 补上（readerRunning 已为 true）。
func (s *udpSession) rebindRoute(domain string, route dnsRoute) {
	conn, remote, err := s.dialRoute(s.ctx, domain, route)
	if err != nil {
		// 保留旧连接与旧路由：本次查询继续走旧路径。记 Warn 是因为它意味着
		// 一条本该切换的查询没能切换；rebindCooldown 内的后续查询不再拨号，
		// 因此不会每帧刷一条 Warn。
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
		// 先安装新连接再关旧连接：关闭会让旧连接的读取 goroutine 退出，而它
		// 退出时看到 s.upstream() 已不是自己，因此不会把这次关闭当成目标故障。
		old.Close() //nolint:errcheck
	}
}

// logUpstreamConnected 记录一条刚建立的出站连接。两条安装路径（首条连接与
// 重绑）共用它，使日志字段只有一份定义。
func logUpstreamConnected(target, remote string, route dnsRoute) {
	log.Info("[UDP] upstream connected", "target", target, "remote", remote,
		"via_next_proxy", route.viaNextProxy())
}

// observeDNSFrame 处理一个 DATAGRAM 载荷：判定路由、按需重绑、并打开应答学习。
// 它由 udpSession.observeClientFrame 在写入目标之前调用，因此调用返回后
// "该往哪条连接写"已经确定。
func (s *udpSession) observeDNSFrame(payload []byte) {
	if s.dns.enabled {
		// DNS 会话：每条查询的 QNAME 都可能改变出站路由。
		s.noteDNSQuery(payload)
		return
	}
	// 非 DNS 会话只在第一个数据报上判定一次：一个会话只承载一次 DNS 查询的开端，
	// 后续数据报（QUIC 等）不该再被解析。
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

// targetRoute 返回**按目标**判定的路由，与 dialTarget 用的是同一个 shouldProxy
// 谓词。会话建立时就已按目标拨号的场景（非 DNS 会话、未配置下一级代理的 DNS
// 会话）读它：日志与"连接实际怎么拨的"因此不会各说各话。
//
// 它是 udp_dns.go 里唯一按目标判定的入口；udp.go 不再自带一份副本。
func (s *udpSession) targetRoute() dnsRoute {
	if s.nextProxy != nil && s.nextProxy.EnableUDP() && s.nextProxy.ShouldProxy(s.target) {
		return dnsRouteNextProxy
	}
	return dnsRouteDirect
}

// noteDNSQuery 在 DNS 会话里处理一条查询：路由判定与路由变化后的重绑。
// 它是主 goroutine 私有的状态转换，与数据报的发送顺序一致。
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

	// 重绑的判据是"当前连接的路由与这条查询要求的不一致"，而不是"与上一条查询
	// 不一致"：后者会漏掉"首帧畸形 → 直连兜底 → 首条真实查询"这条序列（兜底
	// 时没有查询、也就没有 routeSel 可供比较），让命中代理的查询被写进直连连接。
	// connRoute 与 conn 由同一个锁保护，因此这里读到的路由一定属于当前连接。
	connRoute, hasRoute := s.upstreamRoute()
	changed := hasRoute && connRoute != route
	if changed {
		if s.rebindCoolingDown() {
			// 冷却中：不重复拨号，本帧继续走旧连接。日志会带 route_pending=true。
			s.logDNSRoute(domain, route, changed)
			return
		}
		s.rebindRoute(domain, route)
	}
	// 日志在重绑之后输出，并读**当前连接**的路由：重绑失败时旧连接被保留，
	// via_next_proxy 必须反映这条查询实际走的那条路，而不是它希望走的那条。
	s.logDNSRoute(domain, route, changed)
}

// rebindCooldown 是重绑拨号失败后的静默窗口。取值与 DialTimeout 的量级匹配
// （3~15s）：太短会让每个查询都重新吃满一次拨号超时，太长会让 next proxy
// 恢复后迟迟切不回去。窗口内命中同一路由的查询直接复用旧连接。
const rebindCooldown = 10 * time.Second

// rebindCoolingDown 报告是否仍在上一次重绑失败的冷却窗口内。
// 它只由主 goroutine 调用，因此 rebindFailedAt 不需要额外同步。
func (s *udpSession) rebindCoolingDown() bool {
	return !s.dns.rebindFailedAt.IsZero() &&
		time.Since(s.dns.rebindFailedAt) < rebindCooldown
}

// logDNSRoute 输出一条 DNS 查询实际使用的出站路径。
//
// via_next_proxy 优先读**当前连接**的路由，而不是 routeForDomain 的判定结果：
// 重绑失败时会保留旧连接，此时这条查询实际被写进旧路径，日志必须说旧路径，
// 否则排障时会被"日志说走了代理、实际走了直连"误导。判定结果与连接路由不一致
// 时另带 route_pending=true，表示下一帧还会再次尝试重绑。
//
// 会话还没有连接时（首条查询）退回使用 want：这条查询马上会在 upstreamOrDial
// 里按 routeSel 拨号，因此 want 就是它将走的路径；此时若拨号失败，随后的错误
// 日志与 upstream connected 缺失会说明它并没有建立。
//
// 日志级别按"是否值得留痕"分：判定为需要换路由的查询记 Info（它决定了出站路径，
// 连接建立本身另有 upstream connected 日志）；路由未变化的后续查询记 Debug。
// 客户端把同一 socket 的所有查询复用在一条流上，全部记 Info 会让日志量随查询数
// 增长。重绑失败时另有一条 Warn（见 rebindRoute），因此这里不再重复告警。
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
