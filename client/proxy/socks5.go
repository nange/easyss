package proxy

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/txthinking/socks5"

	easydns "github.com/nange/easyss/v3/client/dns"
)

type Socks5Server struct {
	srv *socks5.Server

	handler           *StreamHandler
	router            *router.Router
	policy            *routePolicy
	dns               *dnsInterceptor
	method            protocol.Method
	disableQUIC       bool
	directDialContext func(context.Context, string, string) (net.Conn, error)
	dialTimeout       time.Duration
	// streamIdleTimeout 限制直连 TCP 中继的空闲时长；由用户配置的基础超时经
	// config.StreamIdleTimeout 派生而来，使直连路径与代理路径的流空闲超时一致。
	streamIdleTimeout time.Duration

	// udp 管理两类 UDP 会话（经隧道的代理交换与直连 socket）及其空闲回收；
	// SOCKS5 UDP 中继与 DNS 拦截共用它（见 udp_pool.go）。
	udp            *udpPool
	udpIdleTimeout time.Duration
	// started 记录 Start 已被派发（见 MarkStarted）：Close 依赖它区分
	// "从未启动"与"启动后立刻关闭"两条路径（见 socks5_lifecycle.go）。
	started atomic.Bool
}

// Socks5Options 用于配置 NewSocks5Server。它取代了一个已增长到十四个参数的
// 位置参数列表——其中四个从同一个基础超时派生的时长可能被悄悄弄混。
type Socks5Options struct {
	ListenAddr string
	Username   string
	Password   string
	Handler    *StreamHandler
	Router     *router.Router
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
		handler:           opts.Handler,
		router:            opts.Router,
		method:            opts.Method,
		disableQUIC:       opts.DisableQUIC,
		directDialContext: directDialContext,
		dialTimeout:       dialTimeout,
		streamIdleTimeout: streamIdleTimeout,
		udpIdleTimeout:    udpIdleTimeout,
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
		DialTimeout:  dialTimeout,
		RespTimeout:  opts.Timeouts.DNSResp,
		QueryIdle:    udpIdleTimeout,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.directDialContext(ctx, network, addr)
		},
	})
	srv, err := socks5.NewClassicServer(opts.ListenAddr, "127.0.0.1", opts.Username, opts.Password, 0, 0)
	if err != nil {
		return nil, err
	}
	s.srv = srv
	return s, nil
}

func defaultDirectDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}

func (s *Socks5Server) TCPHandle(srv *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdUDP {
		caddr, err := r.UDP(c, srv.ServerAddr)
		if err != nil {
			log.Error("[SOCKS5] udp associate failed", "client", c.RemoteAddr().String(), "err", err)
			return err
		}
		log.Debug("[SOCKS5] udp associate", "client", c.RemoteAddr().String(), "udp", caddr.String())
		ch := make(chan byte)
		srv.AssociatedUDP.Set(caddr.String(), ch, -1)
		defer srv.AssociatedUDP.Delete(caddr.String())
		io.Copy(io.Discard, c) //nolint:errcheck
		log.Debug("[SOCKS5] udp associate tcp closed", "udp", caddr.String())
		return nil
	}

	if r.Cmd != socks5.CmdConnect {
		return s.replyError(c, r, socks5.RepCommandNotSupported)
	}

	target := r.Address()
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		log.Error("[SOCKS5] parse target", "target", target, "err", err)
		return s.replyError(c, r, socks5.RepServerFailure)
	}

	// 拦截 DNS over TCP：发往 53 端口的连接按查询域名分流（与 UDP DNS 拦截一致）。
	// 否则解析器走 TCP 时（如 systemd-resolved 特性集降级）DNS 查询会按目标 IP 判
	// 直连、从物理网卡发出而绕过隧道，被 GFW 污染。
	if port == "53" {
		return s.handleTCPDNS(c, r, target, host)
	}

	return s.routeTCP(c, r, target, host)
}

// routeTCP 对已完成 SOCKS5 CONNECT 的 TCP 连接执行 Block/Direct/Proxy 分流。
// 正常路径与 TCP DNS 拦截的回退路径共用；判定与 HTTP 入口共用同一个
// routePolicy（见 route.go）。
func (s *Socks5Server) routeTCP(c net.Conn, r *socks5.Request, target, host string) error {
	decision := s.policy.decide(host)
	if decision.IPV6Rejected {
		logRouteIPV6Rejected("[TCP]", target)
		return s.replyError(c, r, socks5.RepNotAllowed)
	}
	logRouteDecision("[TCP]", decision, host, target, c.RemoteAddr().String())

	switch decision.Action {
	case routeBlock:
		return s.replyError(c, r, socks5.RepNotAllowed)
	case routeDirect:
		rc, err := s.directTCPConnect(c, r, target)
		if err != nil {
			log.Error("[TCP] direct connect", "target", target, "err", err)
			return err
		}
		defer rc.Close() //nolint:errcheck
		relayTCP(rc, c, s.policy.streamIdle())
		log.Debug("[TCP] direct relay finished", "target", target)
		return nil
	default:
		if err := writeSocksSuccessReply(c); err != nil {
			log.Error("[TCP] proxy reply", "err", err)
			return err
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

// writeSocksSuccessReply 向客户端写 SOCKS5 CONNECT 成功应答，地址取自本地监听
// 地址（与代理路径一致，供 TCP DNS 拦截复用）。
func writeSocksSuccessReply(c net.Conn) error {
	a, bindAddr, bindPort, err := socks5.ParseAddress(c.LocalAddr().String())
	if err != nil {
		return err
	}
	if a == socks5.ATYPDomain {
		bindAddr = bindAddr[1:]
	}
	p := socks5.NewReply(socks5.RepSuccess, a, bindAddr, bindPort)
	_, err = p.WriteTo(c)
	return err
}

func (s *Socks5Server) directTCPConnect(c net.Conn, r *socks5.Request, target string) (net.Conn, error) {
	rc, err := s.policy.dialDirect(target)
	if err != nil {
		_ = s.replyError(c, r, socks5.RepHostUnreachable)
		return nil, err
	}

	a, bindAddr, bindPort, err := socks5.ParseAddress(rc.LocalAddr().String())
	if err != nil {
		rc.Close() //nolint:errcheck
		_ = s.replyError(c, r, socks5.RepHostUnreachable)
		return nil, err
	}
	if a == socks5.ATYPDomain {
		bindAddr = bindAddr[1:]
	}
	p := socks5.NewReply(socks5.RepSuccess, a, bindAddr, bindPort)
	if _, err := p.WriteTo(c); err != nil {
		rc.Close() //nolint:errcheck
		return nil, err
	}

	return rc, nil
}

func (s *Socks5Server) UDPHandle(srv *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	return s.handleUDP(srv, addr, d)
}

func (s *Socks5Server) replyError(c net.Conn, r *socks5.Request, rep byte) error {
	var p *socks5.Reply
	if r.Atyp == socks5.ATYPIPv4 || r.Atyp == socks5.ATYPDomain {
		p = socks5.NewReply(rep, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
	} else {
		p = socks5.NewReply(rep, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0, 0})
	}
	_, err := p.WriteTo(c)
	return err
}
