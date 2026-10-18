package handler

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util/bytespool"
)

const udpBufSize = protocol.MaxUDPDataSize

// udpHandler 是 UDP 端点的 handler：它持有会话共享的依赖（空闲超时、next
// proxy、出站拨号器），并为每条流创建一个 udpSession。
type udpHandler struct {
	idleTimeout time.Duration
	// nextProxy 在这里单独保存（而不仅存在于 dial 内部），因为只有 UDP
	// 会在数据报流上用它进行 DNS 应答学习，与当前目标是否经由它路由无关。
	nextProxy *nextproxy.NextProxy
	dial      dialer
	// route 是 DNS 查询的路由判定与拨号（见 udp_dns.go）。nextProxy 为 nil
	// 时它也是 nil，所有查询直接出网。
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
	directDialer := outboundDialer(config.DialTimeout(timeout), 0)
	h := &udpHandler{idleTimeout: idleTimeout, nextProxy: np}
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
		ctx:         ctx,
		idleTimeout: h.idleTimeout,
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

	dr         *crypto.DecryptedReader
	s2c        shaper.Shaper
	cancelRead func()
	// ctx 是 Handle 的请求上下文。DNS 会话的首条查询与每次重绑都要拨号，而
	// 拨号只发生在主循环上，因此这里持有它是安全的；它让"客户端已经断开"能
	// 中止一次进行中的拨号，而不是白等到拨号超时。
	ctx         context.Context
	idleTimeout time.Duration
	nextProxy   *nextproxy.NextProxy
	dial        dialer
	// dns 是这个会话的 DNS 状态：是否按查询域名路由、当前连接用的路由、以及
	// 应答学习门控（见 udp_dns.go）。非 DNS 会话里它只承载学习门控。
	dns dnsState

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

	// transferred 是服务端到客户端方向已推送的载荷字节数。它只由主
	// goroutine 写入（读取侧经 resultCh 回传后累加），因此没有并发访问。
	transferred int64
}

// udpSessionConfig 是 udpSession 的构造参数。
type udpSessionConfig struct {
	conn   net.Conn
	remote string
	target string
	// dnsSession 表示目标是 53 端口：出站连接由查询域名决定，可中途重绑。
	dnsSession bool
	dr         *crypto.DecryptedReader
	s2c        shaper.Shaper
	cancelRead func()
	// ctx 是 Handle 的请求上下文。DNS 会话的首条查询与每次重绑都要拨号，而
	// 拨号只发生在主循环上，因此这里持有它是安全的；它让"客户端已经断开"能
	// 中止一次进行中的拨号，而不是白等到拨号超时。
	ctx         context.Context
	idleTimeout time.Duration
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
		dr:          cfg.dr,
		s2c:         cfg.s2c,
		cancelRead:  cfg.cancelRead,
		ctx:         cfg.ctx,
		idleTimeout: cfg.idleTimeout,
		nextProxy:   cfg.nextProxy,
		dial:        cfg.dial,
		dns:         dnsState{enabled: cfg.dnsSession, router: cfg.route},
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

// remoteAddr 在锁下取当前连接的远端地址，供读取 goroutine 记日志使用
// （setUpstream 会在重绑时改写它）。
func (s *udpSession) remoteAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remote
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

	// DNS 侧的判定（学习门控、路由选择、按需重绑）在 udp_dns.go；它返回时
	// "这条数据报该往哪条连接写"已经确定。
	s.observeDNSFrame(f.Payload)

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
	// 有路由判定能力的 DNS 会话按当前查询选定的路由（首帧不是合法查询时
	// routeSel 仍是零值，即直连兜底——随后真正的查询会因与 connRoute 不一致
	// 而重绑）；其他会话（含未配置下一级代理的 DNS 会话）按目标一次性判定，
	// 与 dialTarget 同源。
	route := dnsRouteDirect
	if s.dns.enabled && s.dns.router != nil {
		route = s.dns.routeSel
	} else if !s.dns.enabled {
		route = s.targetRoute()
	}
	if err := s.dialUpstream(s.ctx, s.dns.dialDomain, route); err != nil {
		return nil, err
	}
	conn = s.upstream()
	if conn == nil {
		return nil, errors.New("udp upstream not established")
	}
	return conn, nil
}

// dialUpstream 按给定路由拨号出站连接。这是会话里唯一建立出站连接的地方：
// 建立（DNS 会话的首条查询、非 DNS 会话的 Handle）与重绑（rebindRoute）共用它，
// 因此"判定—拨号—记录路由与远端"只有一套。
//
// 路由是参数而不是从会话状态里推出来的：DNS 会话的兜底拨号（首帧不是查询）与
// 查询驱动的拨号走的是同一条路径，区别只在路由由谁决定。
func (s *udpSession) dialUpstream(ctx context.Context, domain string, route dnsRoute) error {
	// 有 dnsRouter 时全部交给它：判定与拨号必须同源，两条路由都由它分派
	// （udpRouteDialer.dialRoute 内部对直连路由走共享 dialer 的直连分支）。
	// 没有它时（未配置下一级代理、或其他会话）由会话自己按路由拨。
	// 装连接与启动读取侧都在 dialRoute 里（见 udp_dns.go）。
	remote, err := s.dialRoute(ctx, domain, route)
	if err != nil {
		return err
	}
	log.Info("[UDP] upstream connected", "target", s.target, "remote", remote,
		"via_next_proxy", route.viaNextProxy())
	return nil
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
	// 读满整个池档位：n == len(readBuf) 说明数据报至少填满了档位（被截断，
	// 或恰好等于档位），两者都超过 udpBufSize，丢弃而不是把截断的应答转发给
	// 客户端。只读 16,362 字节则无法区分"恰好等于预算"与"被截断"。
	readBuf := buf[:cap(buf)]

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
		n, err := conn.Read(readBuf)
		if err != nil {
			if protocol.IsUDPMessageTooLong(err) {
				log.Warn("[UDP] dropping oversized datagram", "err", err)
				continue
			}
			if conn != s.upstream() {
				// 这条连接已经被重绑替换：它的错误是拆连接的预期结果，不是目标
				// 故障，也不该拿去结束会话——新连接的读取 goroutine 已经接手。
				return
			}
			s.sendResult(udpDatagram{err: s.targetReadError(err)})
			return
		}
		if n > udpBufSize {
			log.Warn("[UDP] dropping oversized datagram", "n", n,
				"limit", udpBufSize, "truncated", n == len(readBuf))
			continue
		}
		payload := append([]byte(nil), readBuf[:n]...)
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
	log.Error("[UDP] read from target failed", "target", s.remoteAddr(), "err", err)
	return err
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
