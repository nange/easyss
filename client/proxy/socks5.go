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

// 地址不提前解析，使路由判定拿到原始目标。
type socks5Frame struct {
	cmd    byte
	target string
}

// SOCKS5 应答码；RepNotAllowed 与 RepRuleFailure 同为 0x02。
const (
	repSuccess              = statute.RepSuccess
	repServerFailure        = statute.RepServerFailure
	repNotAllowed           = statute.RepRuleFailure
	repHostUnreachable      = statute.RepHostUnreachable
	repCommandNotSupported  = statute.RepCommandNotSupported
	repAddrTypeNotSupported = statute.RepAddrTypeNotSupported
)

// BND.ADDR/BND.PORT 取自 bindAddr，失败应答按 RFC 1928 回 IPv4 零地址；不复用库的
// SendReply，因为它把成功应答的地址也写死成 IPv4。
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

func writeSocksSuccessReply(c net.Conn) error {
	return writeSocksReply(c, repSuccess, c.LocalAddr())
}

// 先消费库的缓冲、再落到底层连接；按 io.Reader 持有，因为库的 Request.Reader 不保证是 *bufio.Reader。
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

// 必须显式转发：copyHalfClose（route.go）对客户端连接做 CloseWrite 鸭子断言，
// 不实现就静默跳过，远端的 FIN 传不出去。
func (s *socks5Stream) CloseWrite() error {
	if cw, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("socks5Stream: %T does not support CloseWrite", s.Conn)
}

// 返回 nil IP 且不报错即可让库保留 FQDN；默认 resolver 会提前解析，router.ClassifyHost 就拿不到域名了。
type passthroughResolver struct{}

func (passthroughResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

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
	// streamIdleTimeout 限制直连 TCP 中继的空闲时长，与代理路径的流空闲超时同源。
	streamIdleTimeout time.Duration

	// udp 管理两类 UDP 会话（隧道交换与直连 socket）及其空闲回收，中继与 DNS 拦截共用。
	udp            *udpPool
	udpIdleTimeout time.Duration

	listenAddr string

	// 全部存活的 UDP ASSOCIATE 中继；tun2socks 为每条 UDP 流各建一个关联。
	udpMu           sync.RWMutex
	udpRelays       map[*udpRelay]struct{}
	udpRelaysClosed bool // Close 之后拒绝登记新中继，见 addUDPRelay

	// 库不提供 Shutdown，监听器由 Start 创建、Close 关闭。
	listenerMu sync.Mutex
	listener   net.Listener
	closed     bool

	closeOnce sync.Once
	closeErr  error
}

// Handler/Router/DirectDialContext 一律借用（与 HTTP 入口共用），本类型只负责监听器与 UDP 会话。
type Socks5Options struct {
	ListenAddr string
	Username   string
	Password   string
	Handler    *StreamHandler
	Router     *router.Router
	// ServerDomain 是代理服务器自身的主机名（字面 IP 时为空），针对它的查询必须直连。
	ServerDomain string
	Method       protocol.Method
	// DisableQUIC 启用后所有发往 443 端口的 UDP 数据报都被丢弃，与路由规则无关。
	DisableQUIC bool
	Timeouts    config.Timeouts
	// DNSCache 是调用方（runner）持有的共享缓存；为 nil 时按 ServerDomain 自建。
	DNSCache          *easydns.Cache
	DirectDialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// DisableDNSIntercept 关闭"发往 53 端口的连接按 DNS 处理"的拦截。VPN 对端面必须
	// 打开它：那里 53 是普通服务端口，被拦截会按查询域名重新分流，与对端面"只拨字面
	// loopback"的契约冲突。
	DisableDNSIntercept bool
	// DisableUDPAssociate 关闭 UDP ASSOCIATE（一律回 RepCommandNotSupported）。
	// VPN 对端面的 UDP 走 tailcat UDP listener + 薄中继（见 vpn/node/udprelay.go），
	// 不能依赖"绑不上 tailcat ULA 而失败"的副作用。
	DisableUDPAssociate bool
	// VPN 是访问侧的 VPN 注入面；为 nil 时 VPN 分流完全关闭。非 nil 时命中对端的
	// 目标走隧道（见 VPNRoute）。
	VPN VPNRoute
}

func NewSocks5Server(opts Socks5Options) (*Socks5Server, error) {
	// 零值填充只发生在这里：下面的会话池与 DNS 拦截器都只读归一化后的字段。
	timeouts := opts.Timeouts.Normalize()
	dialTimeout := timeouts.Dial
	udpIdleTimeout := timeouts.UDPIdle
	streamIdleTimeout := timeouts.StreamIdle
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
	// dial 晚绑定到 s.directDialContext，使会话池与 DNS 拦截器只看到一个拨号函数。
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
		Timeouts:     timeouts,
		// 静态名钩子只为对端名字提供本地应答：TUN 下系统解析器的查询到达的是这里，
		// 而不是 client/dns 的转发服务器（见 dnsOptions.Static）。
		Static: vpnStaticNames(opts.VPN),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.directDialContext(ctx, network, addr)
		},
	})

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
		// 域名必须在业务层判定（见 passthroughResolver）。
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

// 库在调用它之前不写任何应答，因此时机与应答码都由本函数决定。
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

	// 流水线客户端的首批载荷可能已落在库的 r.Reader 里，直接读裸连接会静默丢掉那些字节。
	stream := newSocks5Stream(c, r.Reader)

	// VPN 对端优先于 53 拦截：对端本机监听在 53 的服务在 UDP 侧可达，TCP 侧若被本机
	// 拦截器吞掉就不对称。VPN 对端面也会关掉下面的拦截（见 Socks5Options.DisableDNSIntercept）。
	if s.isVPNPeer(host) {
		return s.routeTCP(stream, target, host)
	}

	// 发往 53 端口的连接按查询域名分流，否则解析器走 TCP 时查询会按目标 IP 判直连、
	// 从物理网卡发出而绕过隧道。
	if port == "53" && !s.disableDNSIntercept {
		return s.handleTCPDNS(stream, target, host)
	}

	return s.routeTCP(stream, target, host)
}

// isVPNPeer 报告 host 是否为本机配置的 VPN 对端：53 拦截与 QUIC 屏蔽都按它让路。
func (s *Socks5Server) isVPNPeer(host string) bool {
	if s.vpn == nil {
		return false
	}
	_, ok := s.vpn.Lookup(host)
	return ok
}

// routeTCP 对已完成 SOCKS5 CONNECT 的 TCP 连接执行 Block/Direct/Proxy 分流。
// 正常路径与 TCP DNS 拦截的回退路径共用；判定与 HTTP 入口共用同一个 routePolicy。
func (s *Socks5Server) routeTCP(c net.Conn, target, host string) error {
	return s.routeTCPReplied(c, target, host, false)
}

// replied 表示成功应答已写出（TCP DNS 拦截先应答再首读）；已应答时任何分支都不再写，
// 第二个应答会被客户端当成上层数据、污染流。
func (s *Socks5Server) routeTCPReplied(c net.Conn, target, host string, replied bool) error {
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

// replied 为 true 时成功应答已写出，不再补写。
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

func (s *Socks5Server) replyError(c net.Conn, code uint8) error {
	return writeSocksReply(c, code, nil)
}

// vpnTCPConnect 经 VPN 隧道打开到对端的连接；replied 的语义与 directTCPConnect 一致。
// BND.ADDR 刻意回报 nil——隧道连接的 LocalAddr 是 WireGuard ULA，对客户端无意义；
// 可达性由内层握手决定，且已在本调用返回前完成。
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

// 库的默认实现会把数据报直接转发，因此自建 socket 并自持会话池；客户端地址以发起
// ASSOCIATE 的 TCP 对端为准（RFC 1928）。
func (s *Socks5Server) associateHandler(_ context.Context, writer io.Writer, _ *thingssocks5.Request) error {
	c, ok := writer.(net.Conn)
	if !ok {
		return fmt.Errorf("socks5 associate: writer is %T, not net.Conn", writer)
	}
	return s.udpAssociate(c)
}

// associateDisabled 是 DisableUDPAssociate 的 handler：按 RFC 1928 回
// RepCommandNotSupported，而不是断开连接——客户端会得到一个明确的"不支持该命令"。
func (s *Socks5Server) associateDisabled(_ context.Context, writer io.Writer, _ *thingssocks5.Request) error {
	c, ok := writer.(net.Conn)
	if !ok {
		return fmt.Errorf("socks5 associate: writer is %T, not net.Conn", writer)
	}
	log.Debug("[SOCKS5] UDP ASSOCIATE disabled on this entry")
	return s.replyError(c, repCommandNotSupported)
}

// 循环运行到 TCP 控制连接断开，这正是 RFC 1928 的关联生命周期。
func (s *Socks5Server) udpAssociate(c net.Conn) error {
	// 端口用 0 让内核分配，真实端口通过 BND.PORT 通告。tun2socks 为每条 UDP 流单独发起一次
	// ASSOCIATE，绑固定端口会让第二条直接 EADDRINUSE。
	tcpAddr, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		_ = s.replyError(c, repServerFailure)
		return fmt.Errorf("local address is not TCP: %T", c.LocalAddr())
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: tcpAddr.IP})
	if err != nil {
		_ = s.replyError(c, repServerFailure)
		return fmt.Errorf("listen udp associate: %w", err)
	}

	// 只取 TCP 对端的 IP 作为唯一被接受的 UDP 来源：客户端 UDP 源端口通常与 TCP 端口不同。
	remote, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		uc.Close() //nolint:errcheck
		_ = s.replyError(c, repServerFailure)
		return fmt.Errorf("remote address is not TCP: %T", c.RemoteAddr())
	}
	clientIP := remote.IP

	// 先登记再回 success：登记失败时应回失败应答，而不是一个指向立刻关闭 socket 的 BND 地址。
	// 登记与 Close 的 udpRelaysClosed 检查必须同锁，否则 Close 扫过表之后插入的 socket 没人关。
	relay := &udpRelay{socket: uc, clientIP: clientIP}
	if !s.addUDPRelay(relay) {
		uc.Close() //nolint:errcheck
		_ = s.replyError(c, repServerFailure)
		return errSocksServerClosed
	}
	if err := writeSocksReply(c, repSuccess, uc.LocalAddr()); err != nil {
		s.removeUDPRelay(relay)
		return err
	}
	log.Debug("[SOCKS5] udp associate", "client", c.RemoteAddr().String(), "udp", uc.LocalAddr().String())

	// 关联在承载它的 TCP 控制连接终止时结束，而中继循环阻塞在 UDP 读取上看不见它。
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
		// 中继循环先退出时控制连接可能仍打开，这里主动关闭它唤醒那个监视 goroutine。
		c.Close() //nolint:errcheck
		log.Debug("[SOCKS5] udp associate tcp closed", "udp", uc.LocalAddr().String())
	}()
	s.udpRelayLoop(relay)
	return nil
}

// socket 必须随调用链传递：多个关联并行存在，全局状态会把应答写到别的关联的 socket 上。
type udpRelay struct {
	socket *net.UDPConn
	// clientIP 只用于来源过滤，端口不参与过滤。
	clientIP net.IP
	// 应答必须写回这里：clientIP 来自 TCP 控制连接、端口无意义，异步应答靠它回到正确端点。
	peerMu sync.RWMutex
	peer   *net.UDPAddr
}

func (r *udpRelay) datagramSource() *net.UDPAddr {
	r.peerMu.RLock()
	defer r.peerMu.RUnlock()
	return r.peer
}

func (r *udpRelay) setDatagramSource(addr *net.UDPAddr) {
	r.peerMu.Lock()
	r.peer = addr
	r.peerMu.Unlock()
}

// 返回 false 表示服务器已关闭，调用方必须自行关闭 socket；检查与插入必须和
// closeUDPRelays 的扫描同锁。
func (s *Socks5Server) addUDPRelay(r *udpRelay) bool {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	if s.udpRelaysClosed {
		return false
	}
	if s.udpRelays == nil {
		s.udpRelays = make(map[*udpRelay]struct{})
	}
	s.udpRelays[r] = struct{}{}
	return true
}

func (s *Socks5Server) removeUDPRelay(r *udpRelay) {
	s.udpMu.Lock()
	if s.udpRelays != nil {
		delete(s.udpRelays, r)
	}
	s.udpMu.Unlock()
	r.socket.Close() //nolint:errcheck
}

func (s *Socks5Server) closeUDPRelays() {
	s.udpMu.Lock()
	s.udpRelaysClosed = true
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

// 只接受来自 ASSOCIATE 请求者 IP 的数据报，避免任意本机进程借这个 socket 发起中继。
func (s *Socks5Server) udpRelayLoop(relay *udpRelay) {
	uc := relay.socket
	buf := bytespool.Get(protocol.MaxUDPDataSize)
	defer bytespool.MustPut(buf)
	// 读满整个池档位而非只读预算长度：MaxUDPDataSize 比档位小 22 字节，因此 n == len(readBuf)
	// 意味着原始数据报超出预算（恰好落在档位边界或被内核截断）。
	readBuf := buf[:cap(buf)]

	for {
		n, src, err := uc.ReadFromUDP(readBuf)
		if err != nil {
			if protocol.IsUDPMessageTooLong(err) {
				log.Warn("[UDP] dropping oversized datagram", "src", src, "err", err)
				continue
			}
			return
		}
		if src == nil || !src.IP.Equal(relay.clientIP) {
			log.Debug("[UDP] datagram from unexpected source dropped", "src", src)
			continue
		}
		relay.setDatagramSource(src)
		if n == len(readBuf) {
			log.Warn("[UDP] dropping truncated datagram", "src", src, "n", n,
				"limit", protocol.MaxUDPDataSize)
			continue
		}
		frame, err := statute.ParseDatagram(readBuf[:n])
		if err != nil {
			log.Debug("[UDP] malformed datagram dropped", "src", src, "err", err)
			continue
		}
		// 分片数据报一律丢弃：RFC 1928 允许 FRAG 非零，但本项目不实现重组。
		if frame.Frag != 0 {
			log.Debug("[UDP] fragmented datagram dropped", "src", src, "frag", frame.Frag)
			continue
		}
		// SOCKS5 头也占整包长度：整包读满档位时，IPv4 头仍可能让解析后的载荷越过预算。
		if len(frame.Data) > protocol.MaxUDPDataSize {
			log.Warn("[UDP] dropping oversized datagram", "src", src,
				"payload", len(frame.Data), "limit", protocol.MaxUDPDataSize)
			continue
		}
		if err := s.handleUDP(relay, &socks5Frame{cmd: statute.CommandAssociate, target: frame.DstAddr.String()}, frame.Data); err != nil {
			log.Debug("[UDP] handle datagram", "src", src, "target", frame.DstAddr.String(), "err", err)
		}
	}
}
