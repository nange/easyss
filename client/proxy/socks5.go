package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/relay"
	"github.com/nange/easyss/v3/util/bytespool"
	"github.com/txthinking/socks5"
	"golang.org/x/sync/singleflight"

	easydns "github.com/nange/easyss/v3/client/dns"
)

type Socks5Server struct {
	srv *socks5.Server

	handler           *StreamHandler
	router            *router.Router
	dnsCache          *easydns.Cache
	serverDomain      string
	method            protocol.Method
	disableQUIC       bool
	directDialContext func(context.Context, string, string) (net.Conn, error)
	dialTimeout       time.Duration
	// streamIdleTimeout 限制直连 TCP 中继的空闲时长；由用户配置的基础超时经
	// config.StreamIdleTimeout 派生而来，使直连路径与代理路径的流空闲超时一致。
	streamIdleTimeout time.Duration

	udpMu   sync.RWMutex
	udpExch map[string]*UDPExchange
	// udpExchangeSF 对相同 (client, target) 键的并发 OpenUDPExchange 调用去重；
	// udpInflightCount 记录正在创建中的数量，使交换数量上限能将其计入。
	udpExchangeSF    singleflight.Group
	udpInflightCount atomic.Int64
	directUDP        map[string]*directUDPConn
	// directUDPSF 对相同 (client, target) 键的并发直连 UDP 拨号去重。
	directUDPSF    singleflight.Group
	quit           chan struct{}
	closeOnce      sync.Once
	udpIdleTimeout time.Duration
	// dnsRespTimeout 限制代理 DNS 交换在没有任何服务器响应的情况下可保持多久
	// 才被关闭（读空闲超时）。只有 DNS 交换启用它；0 表示禁用该机制。它存在的
	// 原因是：当客户端不断重试查询（每次 Send 都会刷新 lastSeen）而上游 DNS
	// 服务器一直沉默时，默认 60 秒的 udpIdleTimeout 永远不会触发。
	dnsRespTimeout time.Duration
	started        atomic.Bool
	closing        atomic.Bool
}

// directUDPConn 将直连 UDP socket 与其最近活动时间戳配对，使清理循环能够回收
// 远端已沉默的会话。
type directUDPConn struct {
	conn     net.Conn
	lastSeen atomic.Int64 // UnixNano，每次收发数据报时刷新
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
		dnsCache:          easydns.NewCache(serverDomain),
		serverDomain:      serverDomain,
		method:            opts.Method,
		disableQUIC:       opts.DisableQUIC,
		directDialContext: directDialContext,
		dialTimeout:       dialTimeout,
		streamIdleTimeout: streamIdleTimeout,
		udpExch:           make(map[string]*UDPExchange),
		directUDP:         make(map[string]*directUDPConn),
		quit:              make(chan struct{}),
		udpIdleTimeout:    udpIdleTimeout,
		dnsRespTimeout:    opts.Timeouts.DNSResp,
	}
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

// PrePopulateDNS 用给定域名的解析结果 IP 预先填充 DNS 缓存：依次尝试给定的各个
// DNS 服务器，全部失败时回退到系统 DNS 服务器。这可以避免 TUN 路由生效时出现
// DNS 死锁。
// ctx 约束整个解析过程，使不可达的 DNS 服务器无法阻塞启动
// （参见 dns.Cache.PrePopulateWithFallback）。
func (s *Socks5Server) PrePopulateDNS(ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error {
	return s.dnsCache.PrePopulateWithFallback(ctx, domain, dnsServers, requireIPv4)
}

// isServerDomain 报告给定域名是否是代理服务器自身的主机名。针对它的 DNS 查询
// 绝不能走代理路径：解析服务器域名需要打开隧道流，而打开隧道流又需要拨号到
// 服务器域名——这是一个会死锁的循环依赖（尤其是在系统休眠/唤醒后缓存条目可能
// 已过期时）。
func (s *Socks5Server) isServerDomain(domain string) bool {
	return s.serverDomain != "" && strings.EqualFold(domain, s.serverDomain)
}

// MarkStarted 记录 Start 即将被调用。它必须在以 goroutine 方式启动 Start 之前
// 同步调用：若在 Start 内部设置该标志，在单核调度器上会与 Close 竞争，
// 导致服务器 goroutine 泄漏其监听器。
func (s *Socks5Server) MarkStarted() {
	s.started.Store(true)
}

func (s *Socks5Server) Start() error {
	s.started.Store(true)
	go s.cleanupLoop()
	return s.srv.ListenAndServe(s)
}

// acceptProbeTimeout 限制 waitForAccept 等待 accept 循环就绪的时长。它只在
// "启动 socks5 服务器后紧接着关闭"这一路径上被消耗：服务器已经在运行时第一次
// 探测就会成功，等待时间约等于零。CI 上出现过 accept 循环在一台超载的
// windows-arm64 runner 上迟迟不响应的实例，因此预算给得比一次调度延迟宽松。
const acceptProbeTimeout = 3 * time.Second

// acceptProbeInterval 是两次探测之间的间隔。
const acceptProbeInterval = 20 * time.Millisecond

// errAcceptNotReady 在 accept 循环迟迟未就绪时由 Close 返回：此时 Close 跳过了
// 库的 Shutdown（见下），监听地址与已接受的连接可能尚未释放。
var errAcceptNotReady = errors.New("socks5 server accept loop did not start in time; shutdown skipped")

// waitForAccept 轮询监听地址，直到服务器真正开始接受连接，报告 accept 循环是否
// 在预算内就绪。单纯的 TCP 拨号不够：只要监听器在内核层面完成绑定它就会成功，
// 而此时 txthinking/socks5 runnergroup 库内部的 accept 循环尚未注册其 runner。
// 在这个窗口内调用 Shutdown 要么泄漏监听器（尚未添加任何 runner 时
// runnergroup.Done 会提前返回），要么死锁（Done 会跳过启动 goroutine 尚未运行的
// runner，然后永远阻塞等待一个永远不会到来的完成信号）。只有用真实的 SOCKS5
// 问候并收到回复来探测，才能证明 accept 循环已经运行：探测成功意味着 runner
// 早已被调度过，因此 Close 永远不会与 Start 派生的 goroutine 竞争。
func (s *Socks5Server) waitForAccept() bool {
	if s.srv == nil {
		return false
	}
	addr := s.srv.Addr
	if addr == "" {
		return false
	}
	// SOCKS5 问候：版本 5，提供一个方法，无认证。只有 accept 循环接受了
	// 我们的连接并解析完问候后，服务器才会应答。
	greeting := []byte{0x05, 0x01, 0x00}
	deadline := time.Now().Add(acceptProbeTimeout)
	for {
		if probeSocks5Accept(addr, greeting) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(acceptProbeInterval)
	}
}

// probeSocks5Accept 拨号 addr 并执行一次 SOCKS5 协商。它报告服务器是否接受了
// 连接并应答了问候，以此证明 accept 循环已启动并完成注册。
func probeSocks5Accept(addr string, greeting []byte) bool {
	c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err != nil {
		return false
	}
	defer c.Close() //nolint:errcheck
	if err := c.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		return false
	}
	if _, err := c.Write(greeting); err != nil {
		return false
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		return false
	}
	return reply[0] == 0x05
}

func (s *Socks5Server) Close() error {
	s.closing.Store(true)
	s.closeOnce.Do(func() { close(s.quit) })
	// accept 循环没能在预算内证明自己已启动时，绝不能调用库的 Shutdown：此刻
	// runnergroup 的启动 goroutine 可能尚未运行，Done 会在 <-g.done 上永久阻塞
	// （2026-09-17 的 windows-arm64 CI 就因此把整个 job 拖到 30 分钟超时）。
	// 宁可跳过关闭并返回错误：调用方要么正在退出进程，要么在下一个测试用例里
	// 用新地址重新开始，而一次卡死会冻结整个客户端。
	if s.started.Load() && !s.waitForAccept() {
		addr := ""
		if s.srv != nil {
			addr = s.srv.Addr
		}
		log.Error("[SOCKS5] accept loop not ready, skip shutdown",
			"addr", addr, "timeout", acceptProbeTimeout)
		return errAcceptNotReady
	}
	var exchanges []*UDPExchange
	s.udpMu.Lock()
	for key, ue := range s.udpExch {
		delete(s.udpExch, key)
		exchanges = append(exchanges, ue)
	}
	for key, dc := range s.directUDP {
		dc.conn.Close() //nolint:errcheck
		delete(s.directUDP, key)
	}
	s.udpMu.Unlock()
	// 在锁外关闭交换：Close 会通过 HTTP/2 流冲刷一个 FIN（一次 io.Pipe 写入），
	// 可能因传输层背压而阻塞——此时持有 s.udpMu 会冻结所有 UDP 处理。
	// closeOnce 保证它与 receiveLoop 自身的 Close 并发时是安全的。
	for _, ue := range exchanges {
		ue.Close() //nolint:errcheck
	}
	// 正在创建中的交换由创建者自己回收：OpenUDPExchange 返回后它会检查关闭
	// 标志，关闭交换并移除工厂条目（参见 getOrCreateUDPExchange）。
	if s.srv != nil {
		return s.srv.Shutdown()
	}
	return nil
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
// 正常路径与 TCP DNS 拦截的回退路径共用。
func (s *Socks5Server) routeTCP(c net.Conn, r *socks5.Request, target, host string) error {
	cls := s.router.ClassifyHost(host)
	if cls.IPV6Rejected {
		log.Warn("[SOCKS5] ipv6 target rejected, ipv6 disabled", "target", target)
		return s.replyError(c, r, socks5.RepNotAllowed)
	}

	local := c.RemoteAddr().String()
	switch cls.Rule {
	case router.HostRuleBlock:
		log.Info("[TCP_BLOCK] blocked", "host", host, "target", target, "local", local)
		return s.replyError(c, r, socks5.RepNotAllowed)
	case router.HostRuleDirect:
		log.Info("[TCP_DIRECT]", "target", target, "local", local)
		rc, err := s.directTCPConnect(c, r, target)
		if err != nil {
			log.Error("[TCP_DIRECT] connect", "target", target, "err", err)
			return err
		}
		defer rc.Close() //nolint:errcheck
		relayTCP(rc, c, s.streamIdleTimeout)
		log.Debug("[TCP_DIRECT] relay finished", "target", target)
		return nil
	case router.HostRuleProxy:
		log.Info("[TCP_PROXY]", "target", target, "local", local)
		if err := writeSocksSuccessReply(c); err != nil {
			log.Error("[TCP_PROXY] reply", "err", err)
			return err
		}
		err := s.handler.OpenTCPStream(context.Background(), target, s.method, c)
		if err != nil {
			if isTransientStreamError(err) {
				log.Debug("[TCP_PROXY] closed", "target", target, "err", err)
				return nil
			}
			log.Error("[TCP_PROXY] stream", "target", target, "err", err)
		} else {
			log.Debug("[TCP_PROXY] stream finished", "target", target)
		}
		return err
	}

	return nil
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
	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
	defer cancel()

	rc, err := s.directDialContext(ctx, "tcp", target)
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

// relayTCP 在 dst 与 src 之间双向拷贝字节，共用一个空闲超时，镜像代理路径的
// 中继语义：干净 EOF 时传播半关闭，空闲超时或出错时两个连接恰好关闭一次。
//
// idleTimeout 限制中继在两条连接被拆除前可保持空闲的时长，使沉默或半开的对端
// 无法让两个拷贝 goroutine 及其 socket 永久存活。调用方由用户配置的基础超时
// 派生它（config.StreamIdleTimeout），使直连路径与代理路径的流空闲超时一致。
func relayTCP(dst, src net.Conn, idleTimeout time.Duration) {
	result := relay.Bidirectional(idleTimeout, relay.CloseBoth(dst, src),
		func(signalActivity func()) error { return copyHalfClose(dst, src, signalActivity) },
		func(signalActivity func()) error { return copyHalfClose(src, dst, signalActivity) },
	)
	logRelayResult("[TCP_DIRECT]", "", result)
}

// logRelayResult 以与结果相匹配的级别记录一次结束的中继：预期的拆除保持静默，
// 超时或拷贝失败记录为 Debug。直连与代理 TCP 路径共用，使同一情况不会被记录为
// 不同级别（直连路径过去会吞掉空闲超时）。
func logRelayResult(prefix, target string, result relay.Result) {
	if result.Err == nil || errors.Is(result.Err, io.EOF) || errors.Is(result.Err, io.ErrClosedPipe) || isLocalConnClosedError(result.Err) {
		return
	}
	if result.TimedOut {
		log.Debug(prefix+" stream idle timeout", "target", target, "err", result.Err)
		return
	}
	log.Debug(prefix+" relay copy error", "target", target, "err", result.Err)
}

// copyHalfClose 将 src 流式拷贝到 dst，每次读取时发出活动信号，并在干净 EOF
// 时对 dst 执行半关闭。
func copyHalfClose(dst, src net.Conn, signalActivity func()) error {
	buf := bytespool.Get(config.TCPStreamBufferSize)
	defer bytespool.MustPut(buf)
	for {
		n, rErr := src.Read(buf)
		if n > 0 {
			signalActivity()
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return wErr
			}
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				if cw, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
				return nil
			}
			return rErr
		}
	}
}

func (s *Socks5Server) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			var stale []*UDPExchange
			s.udpMu.Lock()
			for key, ue := range s.udpExch {
				if time.Since(ue.LastSeen()) > s.udpIdleTimeout {
					log.Debug("[UDP_PROXY] idle cleanup", "key", key)
					delete(s.udpExch, key)
					stale = append(stale, ue)
				}
			}
			// 直连 UDP 会话采用相同的空闲回收：停止响应的远端对端（或已经结束的
			// 数据报流）不应把 socket 及其读取 goroutine 一直占用到读循环自身的
			// 读空闲截止时间触发。
			for key, dc := range s.directUDP {
				if time.Since(time.Unix(0, dc.lastSeen.Load())) > s.udpIdleTimeout {
					log.Debug("[UDP_DIRECT] idle cleanup", "key", key)
					dc.conn.Close() //nolint:errcheck
					delete(s.directUDP, key)
				}
			}
			s.udpMu.Unlock()
			// 在锁外关闭被驱逐的交换：Close 会通过 HTTP/2 流冲刷一个 FIN（一次
			// io.Pipe 写入），可能因传输层背压而阻塞——此时持有 s.udpMu 会冻结
			// 所有 UDP 处理。closeOnce 保证它与 receiveLoop 自身的 Close
			// 并发时是安全的。
			for _, ue := range stale {
				ue.Close() //nolint:errcheck
			}
		case <-s.quit:
			return
		}
	}
}
