package handler

import (
	"context"
	"net"
	"strings"

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
// udpSession.observeClientFrame 调 observeDNSFrame、udpSession.dialUpstream 调
// state.nextProxy。

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
	// （直连兜底），并与 connRoute 一起被用来发现"要换路由"。
	routeSel dnsRoute
	// connRoute 是**当前出站连接**实际使用的路由，nil 表示没有连接（或它已因
	// 路由变化被摘除）。它与 routeSel 相互独立：首帧不是合法查询时（53 端口上的
	// 畸形流量）会话会按直连兜底先拨一条，此后第一条真实查询必须与它比较才能
	// 发现要换路由——只比较连续两条查询的 routeSel 会漏掉这一段。
	connRoute *dnsRoute
	// dialDomain 是最近一次触发路由判定的域名，只用于拨号日志（"是哪条查询
	// 让这条连接走下一级代理的"）。
	dialDomain string

	// 以下是应答学习状态：DNS 会话里每条查询都能直接判定为查询（目标是 53
	// 端口），非 DNS 会话则只在第一个客户端帧上判定一次（一个会话只承载一次
	// DNS 查询的开端）。此后的 DNS 应答才允许被学习。
	//
	// checked 表示"第一个客户端帧"的判定已经完成（只对非 DNS 会话有效）；
	// intercept 表示该会话确实发出过一次 DNS 查询。
	checked   bool
	intercept bool
}

// dialRoute 按给定路由建立出站连接，把它装进会话（并顺带启动读取侧），
// 记录这条连接用的路由（connRoute），返回写给日志的远端地址。
//
// 有 router 时全部交给它：判定与拨号必须同源，两条路由都由它分派（见
// udpRouteDialer.dialRoute，直连路由走共享 dialer 的直连分支）。没有它时
// （未配置下一级代理的会话、非 DNS 会话）由调用方自己的拨号器按路由拨。
func (s *udpSession) dialRoute(ctx context.Context, domain string, route dnsRoute) (string, error) {
	var (
		conn   net.Conn
		remote string
		err    error
	)
	if s.dns.router != nil {
		conn, remote, err = s.dns.router.dialRoute(ctx, "udp", s.target, domain, route)
	} else {
		conn, remote, err = s.dial.dialVia(ctx, "udp", s.target, "", route.viaNextProxy())
	}
	if err != nil {
		return "", err
	}
	s.dns.connRoute = &route
	s.setUpstream(conn, remote, s.readerRunning)
	return remote, nil
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
	changed := s.dns.connRoute != nil && *s.dns.connRoute != route
	logDNSRoute(domain, s.target, route, changed)
	if changed {
		s.rebindRoute(domain)
	}
}

// logDNSRoute 输出一条 DNS 查询的路由判定。via_next_proxy 是这条查询**实际**
// 使用的出站路径，不再是"承载它的会话碰巧怎么拨的"：只有域名命中下一级代理
// 的规则、且 next_proxy.enable_udp 为真时它才为 true。
//
// 日志级别按"是否值得留痕"分：会话首条查询（还没有连接）与改变路由的查询记
// Info——它们决定了出站路径；路由未变化的后续查询记 Debug。客户端把同一 socket
// 的所有查询复用在一条流上，全部记 Info 会让日志量随查询数增长。
func logDNSRoute(domain, target string, route dnsRoute, changed bool) {
	attrs := []any{"domain", domain, "target", target, "via_next_proxy", route.viaNextProxy()}
	if changed {
		log.Info("[UDP_DNS]", append(attrs, "route_changed", true)...)
		return
	}
	log.Debug("[UDP_DNS]", attrs...)
}

// rebindRoute 按新的路由重建出站连接：先摘除并关闭旧连接（读取它的 goroutine
// 会因此返回并退出），再按新路由拨号并为其启动新的读取 goroutine。旧连接上
// 尚未回包的查询由客户端自己重试——DNS 客户端对超时查询的重试是标准行为。
func (s *udpSession) rebindRoute(domain string) {
	s.closeUpstream()
	if err := s.dialUpstream(s.ctx, domain, s.dns.routeSel); err != nil {
		log.Warn("[UDP_DNS] rebind upstream failed", "target", s.target,
			"via_next_proxy", s.dns.routeSel.viaNextProxy(), "err", err)
	}
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
