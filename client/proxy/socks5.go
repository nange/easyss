package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/bytespool"
	thingssocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"

	easydns "github.com/nange/easyss/v3/client/dns"
)

// socks5Frame 是 SOCKS5 请求中本服务器真正需要的字段：命令与目标地址。
// 地址用字符串保存（域名保持原样、不提前解析），使路由判定拿到的始终是客户端
// 请求的原始目标。
type socks5Frame struct {
	cmd    byte
	target string
}

// socks5Reply 映射 SOCKS5 应答码。名字与 RFC 1928 一致，数值与历史实现保持
// 一致（RepNotAllowed == RepRuleFailure == 0x02）。
const (
	repSuccess              = statute.RepSuccess
	repServerFailure        = statute.RepServerFailure
	repNotAllowed           = statute.RepRuleFailure
	repHostUnreachable      = statute.RepHostUnreachable
	repCommandNotSupported  = statute.RepCommandNotSupported
	repAddrTypeNotSupported = statute.RepAddrTypeNotSupported
)

// writeSocksReply 写出一个 SOCKS5 应答。成功应答的 BND.ADDR/BND.PORT 取自
// bindAddr；失败应答按 RFC 1928 回 IPv4 零地址，此时 bindAddr 被忽略。
//
// 有意不复用库的 socks5.SendReply：它把失败应答的 ATYP 硬编码为 IPv4，而本项目
// 历史上对 IPv6 客户端回的是 IPv6 零地址。
func writeSocksReply(w io.Writer, code uint8, bindAddr net.Addr) error {
	frame := statute.Reply{
		Version:  statute.VersionSocks5,
		Response: code,
		BndAddr:  statute.AddrSpec{AddrType: statute.ATYPIPv4, IP: net.IPv4zero, Port: 0},
	}
	if code == statute.RepSuccess {
		switch a := bindAddr.(type) {
		case *net.TCPAddr:
			if a != nil {
				frame.BndAddr.IP, frame.BndAddr.Port = a.IP, a.Port
			}
		case *net.UDPAddr:
			if a != nil {
				frame.BndAddr.IP, frame.BndAddr.Port = a.IP, a.Port
			}
		}
		if frame.BndAddr.IP.To4() != nil {
			frame.BndAddr.AddrType = statute.ATYPIPv4
		} else if frame.BndAddr.IP.To16() != nil {
			frame.BndAddr.AddrType = statute.ATYPIPv6
		}
	}
	_, err := w.Write(frame.Bytes())
	return err
}

// writeSocksSuccessReply 向客户端写 SOCKS5 CONNECT 成功应答，地址取自本地监听
// 地址（与代理路径一致，供 TCP DNS 拦截复用）。
func writeSocksSuccessReply(c net.Conn) error {
	return writeSocksReply(c, repSuccess, c.LocalAddr())
}

// socks5Stream 把库预读过的连接还原成普通 net.Conn：Read 先消费库的缓冲，再落到
// 底层连接。
//
// 不能复用 dnstcp.go 的 bufferedConn：它持的是具体的 *bufio.Reader，而库把
// Request.Reader 暴露为 io.Reader 接口（不同版本的内部实现可能换成别的带缓冲
// 读取器），因此这里按接口持有。
type socks5Stream struct {
	net.Conn
	r io.Reader
}

func newSocks5Stream(c net.Conn, r io.Reader) net.Conn {
	if r == nil {
		return c
	}
	return &socks5Stream{Conn: c, r: r}
}

func (s *socks5Stream) Read(p []byte) (int, error) { return s.r.Read(p) }

// CloseWrite 把半关闭转发到底层连接。
//
// 必须显式转发：copyHalfClose（route.go）在"远端 -> 客户端"方向对客户端连接做
// CloseWrite 鸭子断言，包装器不实现它就会静默跳过，远端的 FIN 传不出去，客户端
// 只能等到空闲超时被硬关（表现为秒级延迟而不是毫秒级）。
func (s *socks5Stream) CloseWrite() error {
	if cw, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("socks5Stream: %T does not support CloseWrite", s.Conn)
}

// passthroughResolver 让库跳过域名解析，把 FQDN 原样交给业务层。
//
// 库在分派到 connect handler 之前会调用 resolver；若使用默认的 DNSResolver，
// 域名会被提前解析成 IP，路由规则（router.ClassifyHost）就拿不到域名了。
// 返回 nil IP 且不报错即可保留 FQDN。
type passthroughResolver struct{}

func (passthroughResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

// socksCredentials 以"用户名与密码都非空才启用认证"的规则实现库的凭证校验，
// 与历史行为一致（只填用户名时视为无认证）。
type socksCredentials struct {
	user     string
	password string
}

func (c socksCredentials) Valid(user, password, _ string) bool {
	return user == c.user && password == c.password
}

type Socks5Server struct {
	srv *thingssocks5.Server

	handler     *StreamHandler
	router      *router.Router
	policy      *routePolicy
	dns         *dnsInterceptor
	method      protocol.Method
	disableQUIC bool
	// disableDNSIntercept 关闭 53 端口拦截（见 Socks5Options.DisableDNSIntercept）。
	disableDNSIntercept bool
	// vpn 是访问侧的 VPN 注入面；nil 表示 VPN 关闭（见 Socks5Options.VPN）。
	vpn               VPNRoute
	directDialContext func(context.Context, string, string) (net.Conn, error)
	dialTimeout       time.Duration
	// streamIdleTimeout 限制直连 TCP 中继的空闲时长；由用户配置的基础超时经
	// config.StreamIdleTimeout 派生而来，使直连路径与代理路径的流空闲超时一致。
	streamIdleTimeout time.Duration

	// udp 管理两类 UDP 会话（经隧道的代理交换与直连 socket）及其空闲回收；
	// SOCKS5 UDP 中继与 DNS 拦截共用它（见 udp_pool.go）。
	udp            *udpPool
	udpIdleTimeout time.Duration

	// listenAddr 是本服务器的 TCP 监听地址，UDP ASSOCIATE 按它绑定同址的 UDP
	// socket（库不再代管 UDP socket，见 udpAssociate）。
	listenAddr string

	// udpMu/udpRelays 保存全部存活的 UDP ASSOCIATE 中继。多个中继必须能长期共存：
	// tun2socks 为每条 UDP 流各建一个关联，它们会并行存在（DNS 与 QUIC、多个上游
	// 的并行查询），任何一个都不该被后来者顶掉。每个中继的 socket 由本服务器创建
	// 并负责关闭。
	udpMu     sync.RWMutex
	udpRelays map[*udpRelay]struct{}

	// listener 由 Start 创建、Close 关闭。库不提供 Shutdown，监听器的生命周期
	// 完全由本类型持有（见 socks5_lifecycle.go）。
	listenerMu sync.Mutex
	listener   net.Listener
	// closed 由 Close 在 listenerMu 下置位，使 Start 与 Close 的竞争有唯一裁决点。
	closed bool

	// closeOnce/closeErr 使 Close 幂等。
	closeOnce sync.Once
	closeErr  error
}

// Socks5Options 用于配置 NewSocks5Server。
//
// 字段的所有权约定（Close 只关闭本类型自己创建的东西）：
//   - Handler/Router/DirectDialContext 一律**借用**：调用方持有它们，并与 HTTP
//     入口共用（见 HTTPProxyOptions），Close 绝不关闭它们；
//   - DNSCache 传入时借用、为 nil 时自建（自建物无需释放）；
//   - 服务器自己创建并负责关闭的只有监听器与 UDP 会话（见 Socks5Server.Close）。
type Socks5Options struct {
	ListenAddr string
	Username   string
	Password   string
	// Handler 是借用的隧道流处理器（由 runner 创建并与 HTTP 入口共用）。
	Handler *StreamHandler
	// Router 是借用的路由引擎（同样与 HTTP 入口共用）。
	Router *router.Router
	// ServerDomain 是代理服务器自身的主机名（为字面 IP 时是 ""）：针对它的 DNS
	// 查询绝不能走代理路径。
	ServerDomain string
	Method       protocol.Method
	// DisableQUIC 置为 true 时屏蔽 QUIC（HTTP/3）：启用后所有发往 443 端口的
	// UDP 数据报都会被丢弃（见 handleUDP），与路由规则无关。
	DisableQUIC bool
	// Timeouts 保存所有派生的时长（拨号、TCP/UDP 空闲、DNS 响应）。参见
	// config.NewTimeouts。
	Timeouts config.Timeouts
	// DNSCache 是调用方（runner）持有的共享 DNS 缓存：预解析（PrePopulate）与
	// DNS pinning 地址发布都由调用方直接驱动，代理服务器只是它的一个使用者。
	// 为 nil 时按 ServerDomain 自建，供独立使用本类型的调用方与测试使用。
	DNSCache *easydns.Cache
	// DirectDialContext 打开直连连接；为 nil 时使用普通的 net.Dialer。
	DirectDialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// DisableDNSIntercept 关闭"发往 53 端口的连接按 DNS 处理"的拦截。
	//
	// 默认关闭该开关（即保持既有行为：53 端口按 DNS over TCP 分流）。VPN 对端面
	// 需要打开它：对端面上 53 是一个普通的服务端口，若仍被 DNS 拦截，对端本机
	// 监听在 53 的服务（如 systemd-resolved）就无法通过 VPN 访问，而且被拦截的
	// 流量会按"查询域名"重新分流，与对端面"只拨字面 loopback"的契约相冲突。
	DisableDNSIntercept bool
	// DisableUDPAssociate 关闭 UDP ASSOCIATE：该命令一律回
	// RepCommandNotSupported（RFC 1928 定义的应答），这个入口只剩 CONNECT。
	//
	// 两个内部入口需要它：VPN 对端面的 UDP 走 tailcat 的 UDP listener + 薄中继
	// （见 vpn/node/udprelay.go），SOCKS5 的 ASSOCIATE 在那里只是"碰巧因为绑不上
	// tailcat ULA 而失败"；内嵌 DERP 的连接由 runner 的 DERP 拨号器直接给出
	// （见 runner/derpdialer.go），根本不经过 SOCKS5。把设计约束写成显式开关，
	// 而不是依赖某个 bind 失败的副作用。
	DisableUDPAssociate bool
	// VPN 是访问侧的 VPN 注入面；为 nil 时 VPN 分流完全关闭，本类型的行为与
	// 引入 VPN 之前逐字节一致。非 nil 时命中对端的目标走隧道（见 VPNRoute）。
	VPN VPNRoute
}

func NewSocks5Server(opts Socks5Options) (*Socks5Server, error) {
	dialTimeout := opts.Timeouts.Dial
	if dialTimeout <= 0 {
		dialTimeout = config.DefaultDialTimeout
	}
	udpIdleTimeout := opts.Timeouts.UDPIdle
	if udpIdleTimeout <= 0 {
		udpIdleTimeout = config.DefaultUDPIdleTimeout
	}
	streamIdleTimeout := opts.Timeouts.StreamIdle
	if streamIdleTimeout <= 0 {
		streamIdleTimeout = config.DefaultStreamIdleTimeout
	}
	directDialContext := opts.DirectDialContext
	if directDialContext == nil {
		directDialContext = defaultDirectDialContext
	}
	serverDomain := opts.ServerDomain
	if net.ParseIP(serverDomain) != nil {
		serverDomain = ""
	}
	s := &Socks5Server{
		handler:             opts.Handler,
		router:              opts.Router,
		method:              opts.Method,
		disableQUIC:         opts.DisableQUIC,
		disableDNSIntercept: opts.DisableDNSIntercept,
		vpn:                 opts.VPN,
		directDialContext:   directDialContext,
		dialTimeout:         dialTimeout,
		streamIdleTimeout:   streamIdleTimeout,
		udpIdleTimeout:      udpIdleTimeout,
		listenAddr:          opts.ListenAddr,
	}
	// dial 以函数值晚绑定到 s.directDialContext：测试会在构造之后替换该字段
	// 作为 seam（见 direct_udp_test.go / dnstcp_test.go），会话池与 DNS 拦截器
	// 只看到一个拨号函数，不依赖 Socks5Server 类型。
	s.udp = newUDPPool(udpPoolOptions{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.directDialContext(ctx, network, addr)
		},
		DialTimeout: dialTimeout,
		IdleTimeout: udpIdleTimeout,
		OpenExchange: func(ctx context.Context, target string, firstPayload []byte) (*UDPExchange, error) {
			return s.handler.OpenUDPExchange(ctx, target, s.method, firstPayload)
		},
	})
	s.policy = newRoutePolicy(routePolicyOptions{
		Router:            opts.Router,
		DialTimeout:       dialTimeout,
		StreamIdleTimeout: streamIdleTimeout,
		VPN:               opts.VPN,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.directDialContext(ctx, network, addr)
		},
	})
	dnsCache := opts.DNSCache
	if dnsCache == nil {
		dnsCache = easydns.NewCache(serverDomain)
	}
	s.dns = newDNSInterceptor(dnsOptions{
		Router:       opts.Router,
		Cache:        dnsCache,
		Pool:         s.udp,
		ServerDomain: serverDomain,
		// VPN 注入面同时（可选地）为对端名字提供本地应答：TUN 模式下系统解析器
		// 的查询正是到达这里，而不是 client/dns 的转发服务器（见 dnsOptions.Static）。
		Static:      vpnStaticNames(opts.VPN),
		DialTimeout: dialTimeout,
		RespTimeout: opts.Timeouts.DNSResp,
		QueryIdle:   udpIdleTimeout,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.directDialContext(ctx, network, addr)
		},
	})

	// 认证方式与历史行为一致：用户名与密码都非空才启用用户名/密码认证。
	authMethods := []thingssocks5.Authenticator{thingssocks5.NoAuthAuthenticator{}}
	if opts.Username != "" && opts.Password != "" {
		authMethods = []thingssocks5.Authenticator{
			thingssocks5.UserPassAuthenticator{
				Credentials: socksCredentials{user: opts.Username, password: opts.Password},
			},
		}
	}

	associate := thingssocks5.Handler(s.associateHandler)
	if opts.DisableUDPAssociate {
		associate = thingssocks5.Handler(s.associateDisabled)
	}

	s.srv = thingssocks5.NewServer(
		thingssocks5.WithAuthMethods(authMethods),
		// 域名必须在业务层判定（见 passthroughResolver），因此让库跳过解析。
		thingssocks5.WithResolver(passthroughResolver{}),
		thingssocks5.WithConnectHandle(thingssocks5.Handler(s.connectHandler)),
		thingssocks5.WithAssociateHandle(associate),
	)
	return s, nil
}

func defaultDirectDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}

// connectHandler 接管 CONNECT 命令：库在调用它之前不写任何应答，因此成功/失败
// 应答的时机与应答码都由本函数决定（TCP DNS 拦截要求"应答先于首读"，见
// handleTCPDNS）。
func (s *Socks5Server) connectHandler(ctx context.Context, writer io.Writer, r *thingssocks5.Request) error {
	c, ok := writer.(net.Conn)
	if !ok {
		return fmt.Errorf("socks5 connect: writer is %T, not net.Conn", writer)
	}
	target := r.RawDestAddr.String()
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		log.Error("[SOCKS5] parse target", "target", target, "err", err)
		return s.replyError(c, repServerFailure)
	}

	// 库用 bufio.Reader 解析握手与请求，因此流水线客户端（把请求与首批载荷合并
	// 成一次写入——DNS over TCP 与带 early data 的 HTTP 客户端都会这么做）的载荷
	// 可能已经落在 r.Reader 的缓冲里。必须从这里继续读：直接读裸连接会把那些字节
	// 静默丢掉。库自带的 handleConnect 正是用 request.Reader 中继的，这是与它一致
	// 的契约。
	stream := newSocks5Stream(c, r.Reader)

	// VPN 对端优先于 53 拦截：对端本机监听在 53 的服务（如 systemd-resolved）在
	// 这里是一个普通服务端口，而不是"按查询域名重新分流"的 DNS。少了这一步，
	// 对端面的 53 在 UDP 侧可达、在 TCP 侧却被本机的拦截器吞掉（见 handleUDP
	// 的同序判定）。
	if s.isVPNPeer(host) {
		return s.routeTCP(stream, target, host)
	}

	// 拦截 DNS over TCP：发往 53 端口的连接按查询域名分流（与 UDP DNS 拦截一致）。
	// 否则解析器走 TCP 时（如 systemd-resolved 特性集降级）DNS 查询会按目标 IP 判
	// 直连、从物理网卡发出而绕过隧道，被 GFW 污染。
	//
	// VPN 对端面会关闭这条拦截（见 Socks5Options.DisableDNSIntercept）：在那里 53
	// 只是一个普通服务端口。
	if port == "53" && !s.disableDNSIntercept {
		return s.handleTCPDNS(stream, target, host)
	}

	return s.routeTCP(stream, target, host)
}

// isVPNPeer 报告 host 是否为本机配置的 VPN 对端。它为"VPN 优先于公网路径门禁"
// 这条规则提供一个共同的判定入口（53 拦截、QUIC 屏蔽都按它让路）。
func (s *Socks5Server) isVPNPeer(host string) bool {
	if s.vpn == nil {
		return false
	}
	_, ok := s.vpn.Lookup(host)
	return ok
}

// routeTCP 对已完成 SOCKS5 CONNECT 的 TCP 连接执行 Block/Direct/Proxy 分流。
// 正常路径与 TCP DNS 拦截的回退路径共用；判定与 HTTP 入口共用同一个
// routePolicy（见 route.go）。
func (s *Socks5Server) routeTCP(c net.Conn, target, host string) error {
	return s.routeTCPReplied(c, target, host, false)
}

// routeTCPReplied 是 routeTCP 的实现。replied 表示 SOCKS5 成功应答是否已经写出：
// TCP DNS 拦截在做首读之前就先应答（见 handleTCPDNS），否则规范客户端会与我们
// 的首读互等。已应答时任何分支都不再写应答——Block/IPv6 门禁只能直接关闭连接，
// 直连拨号失败也只返回错误——因为第二个应答会被客户端当成上层数据，污染流。
func (s *Socks5Server) routeTCPReplied(c net.Conn, target, host string, replied bool) error {
	// reject 写出 SOCKS5 拒绝应答；已经应答过就只能关闭（返回 nil 由调用方关闭）。
	reject := func(reply uint8) error {
		if replied {
			log.Debug("[TCP] rejected after the socks5 reply was already sent, closing", "target", target)
			return nil
		}
		return s.replyError(c, reply)
	}

	decision := s.policy.decide(host)
	if decision.IPV6Rejected {
		logRouteIPV6Rejected("[TCP]", target)
		return reject(repNotAllowed)
	}
	logRouteDecision("[TCP]", decision, host, target, c.RemoteAddr().String())

	switch decision.Action {
	case routeBlock:
		return reject(repNotAllowed)
	case routeDirect:
		rc, err := s.directTCPConnect(c, target, replied)
		if err != nil {
			log.Error("[TCP] direct connect", "target", target, "err", err)
			return err
		}
		defer rc.Close() //nolint:errcheck
		relayTCP(rc, c, s.policy.streamIdle())
		log.Debug("[TCP] direct relay finished", "target", target)
		return nil
	case routeVPN:
		rc, err := s.vpnTCPConnect(c, target, replied)
		if err != nil {
			log.Error("[TCP] vpn connect", "target", target, "err", err)
			return err
		}
		defer rc.Close() //nolint:errcheck
		relayTCP(rc, c, s.policy.streamIdle())
		log.Debug("[TCP] vpn relay finished", "target", target)
		return nil
	default:
		if !replied {
			if err := writeSocksSuccessReply(c); err != nil {
				log.Error("[TCP] proxy reply", "err", err)
				return err
			}
		}
		err := s.handler.OpenTCPStream(context.Background(), target, s.method, c)
		if err != nil {
			if isTransientStreamError(err) {
				log.Debug("[TCP] proxy closed", "target", target, "err", err)
				return nil
			}
			log.Error("[TCP] proxy stream", "target", target, "err", err)
		} else {
			log.Debug("[TCP] proxy stream finished", "target", target)
		}
		return err
	}
}

// directTCPConnect 打开直连并把结果写回客户端。replied 为 true 表示成功应答已
// 经写出（TCP DNS 拦截的回退路径）：此时不再补写应答，拨号失败也只能返回错误，
// 因为客户端已经拿到成功应答，任何后写的应答都会被当成上层数据。
func (s *Socks5Server) directTCPConnect(c net.Conn, target string, replied bool) (net.Conn, error) {
	rc, err := s.policy.dialDirect(target)
	if err != nil {
		if !replied {
			_ = s.replyError(c, repHostUnreachable)
		}
		return nil, err
	}

	if replied {
		return rc, nil
	}

	if err := writeSocksReply(c, repSuccess, rc.LocalAddr()); err != nil {
		rc.Close() //nolint:errcheck
		return nil, err
	}

	return rc, nil
}

// replyError 写出一个 SOCKS5 失败应答。
func (s *Socks5Server) replyError(c net.Conn, code uint8) error {
	return writeSocksReply(c, code, nil)
}

// vpnTCPConnect 经 VPN 隧道打开到对端的连接，并把结果写回客户端。replied 的语义
// 与 directTCPConnect 完全一致（成功应答已写出时不再补写、失败也只能返回错误）。
//
// 与直连路径的唯一区别是 BND.ADDR：这里刻意回报 0.0.0.0:0，而不是隧道连接的
// LocalAddr——那是 WireGuard 的 ULA，对客户端毫无意义（RFC 1928 也允许 CONNECT
// 的 BND.ADDR 不被使用）。真实可达性由"内层握手是否成功"决定，它已经在本调用返回
// 之前完成。
func (s *Socks5Server) vpnTCPConnect(c net.Conn, target string, replied bool) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
	defer cancel()

	rc, err := s.vpn.DialTCP(ctx, target)
	if err != nil {
		if !replied {
			_ = s.replyError(c, repHostUnreachable)
		}
		return nil, err
	}

	if replied {
		return rc, nil
	}
	if err := writeSocksReply(c, repSuccess, nil); err != nil {
		rc.Close() //nolint:errcheck
		return nil, err
	}
	return rc, nil
}

// associateHandler 接管 UDP ASSOCIATE。库不再代管 UDP socket（其默认实现会把
// 数据报直接转发、业务层拿不到内容），改由本服务器自建 socket、自持会话池，从而
// 保留 DNS 拦截、QUIC 屏蔽与按域名分流。
//
// 与库默认实现（things-go/go-socks5 的 handleAssociate）的语义差异：它从
// "监听地址"推导客户端 UDP 地址，而 RFC 1928 要求以发起 ASSOCIATE 的 TCP 对端
// 为准，本实现采用后者。
func (s *Socks5Server) associateHandler(_ context.Context, writer io.Writer, _ *thingssocks5.Request) error {
	c, ok := writer.(net.Conn)
	if !ok {
		return fmt.Errorf("socks5 associate: writer is %T, not net.Conn", writer)
	}
	return s.udpAssociate(c)
}

// associateDisabled 是 DisableUDPAssociate 的 handler：按 RFC 1928 回
// RepCommandNotSupported，而不是断开连接——客户端会得到一个明确的"不支持该
// 命令"，而不是网络错误。
func (s *Socks5Server) associateDisabled(_ context.Context, writer io.Writer, _ *thingssocks5.Request) error {
	c, ok := writer.(net.Conn)
	if !ok {
		return fmt.Errorf("socks5 associate: writer is %T, not net.Conn", writer)
	}
	log.Debug("[SOCKS5] UDP ASSOCIATE disabled on this entry")
	return s.replyError(c, repCommandNotSupported)
}

// udpAssociate 建立 UDP 中继：在与 TCP 入口相同的地址上绑定 UDP socket（与历史
// 行为一致），把成功应答的 BND.ADDR/BND.PORT 通告给客户端，然后启动中继循环。
//
// 中继循环直接运行在本 handler 内、只到 TCP 控制连接断开为止——这正是 RFC 1928
// 定义的 UDP ASSOCIATE 生命周期，且库的 ServeConn 在 handler 返回后才关闭 TCP
// 连接，因此控制连接在整个中继期间保持可用。
func (s *Socks5Server) udpAssociate(c net.Conn) error {
	// 中继 socket 绑定到与 TCP 入口相同的**地址**，但端口用 0 让内核分配：真实端口
	// 通过成功应答的 BND.PORT 通告给客户端（RFC 1928 的客户端按它发包，tun2socks
	// 正是如此）。不能绑固定端口——tun2socks 为每条 UDP 流单独发起一次 ASSOCIATE，
	// 固定端口会让并发的第二条起直接 EADDRINUSE。
	tcpAddr, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		_ = s.replyError(c, repServerFailure)
		return fmt.Errorf("local address is not TCP: %T", c.LocalAddr())
	}
	// 只借用监听地址的 IP，丢弃其端口：未指定地址（0.0.0.0/[::]）在这里保留原样，
	// 由内核按同族选一个地址分配端口。
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: tcpAddr.IP})
	if err != nil {
		_ = s.replyError(c, repServerFailure)
		return fmt.Errorf("listen udp associate: %w", err)
	}

	// TCP 对端的类型是 *net.TCPAddr（不是 UDP），这里只取它的 IP 作为"唯一被接受的
	// UDP 来源"；端口不参与过滤，因为客户端的 UDP 源端口通常与 TCP 端口不同。
	remote, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		uc.Close() //nolint:errcheck
		_ = s.replyError(c, repServerFailure)
		return fmt.Errorf("remote address is not TCP: %T", c.RemoteAddr())
	}
	clientIP := remote.IP

	if err := writeSocksReply(c, repSuccess, uc.LocalAddr()); err != nil {
		uc.Close() //nolint:errcheck
		return err
	}

	// 登记到中继集合。多个关联并存，绝不顶掉已有的中继。
	relay := &udpRelay{socket: uc, clientIP: clientIP}
	s.addUDPRelay(relay)
	log.Debug("[SOCKS5] udp associate", "client", c.RemoteAddr().String(), "udp", uc.LocalAddr().String())

	// RFC 1928：UDP 关联在承载它的 TCP 控制连接终止时结束。中继循环阻塞在 UDP
	// 读取上、看不见 TCP 的关闭，因此这里专门起一个 goroutine 监视控制连接，
	// 一旦断开就关掉本关联的中继 socket——既唤醒中继循环，也立刻释放 UDP 端口。
	go func() {
		var buf [1]byte
		for {
			if _, err := c.Read(buf[:]); err != nil {
				break
			}
		}
		uc.Close() //nolint:errcheck
	}()

	defer func() {
		s.removeUDPRelay(relay)
		// 中继循环先退出（例如服务器 Close 关掉了中继 socket、或数据报处理遇到
		// 致命错误）时，控制连接可能仍然打开——上面那个监视 goroutine 会一直阻塞
		// 在 c.Read 上。这里主动关闭控制连接把它唤醒；读端 socket 一关，Read
		// 必定返回，因此 goroutine 不会滞留在锁上。库的 ServeConn 随后还会再关
		// 一次同一连接，Close 是幂等的。
		c.Close() //nolint:errcheck
		log.Debug("[SOCKS5] udp associate tcp closed", "udp", uc.LocalAddr().String())
	}()
	s.udpRelayLoop(relay)
	return nil
}

// udpRelay 是一次 UDP ASSOCIATE 的中继状态。
//
// socket 必须随调用链传递而不是全局查找：多个关联会并行存在，用"当前中继"这种
// 全局状态会把某个关联的应答错误地写到另一个关联的 socket 上。
type udpRelay struct {
	socket *net.UDPConn
	// clientIP 只用于来源过滤：RFC 1928 的 UDP 中继只服务发起 ASSOCIATE 的客户端，
	// 因此只接受该 IP 发来的数据报（端口不参与过滤——客户端的 UDP 源端口通常与
	// TCP 端口不同）。
	clientIP net.IP
	// peer 是该客户端**实际发来数据报的地址**，应答必须写回这里。它与 clientIP
	// 不同：后者来自 TCP 控制连接、端口无意义，而回包要的是真实 UDP 源地址。
	// 由 udpRelayLoop 在每条数据报到达时刷新，因此异步应答（如 DNS 的代理分支）
	// 也能回到正确的端点。
	peerMu sync.RWMutex
	peer   *net.UDPAddr
}

// datagramSource 返回最近一次收到该客户端数据报的来源地址。
func (r *udpRelay) datagramSource() *net.UDPAddr {
	r.peerMu.RLock()
	defer r.peerMu.RUnlock()
	return r.peer
}

// setDatagramSource 刷新客户端数据报的来源地址。
func (r *udpRelay) setDatagramSource(addr *net.UDPAddr) {
	r.peerMu.Lock()
	r.peer = addr
	r.peerMu.Unlock()
}

// addUDPRelay 登记一个新的中继。
func (s *Socks5Server) addUDPRelay(r *udpRelay) {
	s.udpMu.Lock()
	if s.udpRelays == nil {
		s.udpRelays = make(map[*udpRelay]struct{})
	}
	s.udpRelays[r] = struct{}{}
	s.udpMu.Unlock()
}

// removeUDPRelay 注销一个中继并关闭它的 socket。多次调用是安全的。
func (s *Socks5Server) removeUDPRelay(r *udpRelay) {
	s.udpMu.Lock()
	if s.udpRelays != nil {
		delete(s.udpRelays, r)
	}
	s.udpMu.Unlock()
	r.socket.Close() //nolint:errcheck
}

// closeUDPRelays 供 Close 调用：关闭全部存活的中继。
func (s *Socks5Server) closeUDPRelays() {
	s.udpMu.Lock()
	relays := make([]*udpRelay, 0, len(s.udpRelays))
	for r := range s.udpRelays {
		relays = append(relays, r)
	}
	s.udpRelays = nil
	s.udpMu.Unlock()
	for _, r := range relays {
		r.socket.Close() //nolint:errcheck
	}
}

// udpRelayLoop 读取客户端数据报并交给 handleUDP 分流，直到 socket 关闭。
//
// 只接受来自 ASSOCIATE 请求者 IP 的数据报：RFC 1928 的 UDP 中继只服务那一个
// 客户端，这也避免任意本机进程借这个 socket 发起中继。端口不做限制——客户端
// 的 UDP 源端口通常与其 TCP 端口不同。
func (s *Socks5Server) udpRelayLoop(relay *udpRelay) {
	uc := relay.socket
	buf := bytespool.Get(protocol.MaxUDPDataSize)
	defer bytespool.MustPut(buf)

	for {
		n, src, err := uc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if src == nil || !src.IP.Equal(relay.clientIP) {
			log.Debug("[UDP] datagram from unexpected source dropped", "src", src)
			continue
		}
		// 记下真实来源地址：应答（含异步的 DNS 应答）要写回这里。
		relay.setDatagramSource(src)
		frame, err := statute.ParseDatagram(buf[:n])
		if err != nil {
			log.Debug("[UDP] malformed datagram dropped", "src", src, "err", err)
			continue
		}
		// 分片数据报一律丢弃：RFC 1928 允许 FRAG 非零，但本项目不实现重组
		// （旧库也是在调用业务层之前就把 FRAG != 0 的数据报丢掉的，业务层因此
		// 从来看不到分片）。不丢就会把残缺的分片当成完整载荷中继出去。
		if frame.Frag != 0 {
			log.Debug("[UDP] fragmented datagram dropped", "src", src, "frag", frame.Frag)
			continue
		}
		// handleUDP 的错误只影响这一条数据报，不能中断整个中继循环。
		if err := s.handleUDP(relay, &socks5Frame{cmd: statute.CommandAssociate, target: frame.DstAddr.String()}, frame.Data); err != nil {
			log.Debug("[UDP] handle datagram", "src", src, "target", frame.DstAddr.String(), "err", err)
		}
	}
}
