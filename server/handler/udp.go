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

type udpHandler struct {
	idleTimeout time.Duration
	// UDP 在数据报上做 DNS 应答学习，与目标是否经它路由无关。
	nextProxy *nextproxy.NextProxy
	dial      dialer
	// route 为 nil 时所有查询直接出网。
	route dnsRouter
}

func newUDPHandler(timeouts config.Timeouts, np *nextproxy.NextProxy, deps *outboundDeps) *udpHandler {
	directDialer := outboundDialer(timeouts.Dial, 0)
	h := &udpHandler{idleTimeout: timeouts.UDPIdle, nextProxy: np}
	h.dial = newDialer(np, func(target string) bool {
		return np != nil && np.EnableUDP() && np.ShouldProxy(target)
	}, deps)
	h.dial.dialTimeout = timeouts.Dial
	h.dial.direct = func(ctx context.Context, network, target string) (net.Conn, error) {
		return h.dial.outbound(ctx, directDialer, network, target)
	}
	if np != nil {
		h.route = udpRouteDialer{dialer: h.dial, nextProxy: np}
	}
	return h
}

func (h *udpHandler) Handle(ctx context.Context, dr *crypto.DecryptedReader, s2c shaper.Shaper, target string, cancelRead func()) streamResult {
	log.Debug("[UDP] handler starting", "target", target)

	// 目标是 53 端口时，直连还是走下一级代理只有 QNAME 说了算，因此推迟拨号。
	dnsSession := isDNSPort(target)
	var (
		conn   net.Conn
		remote string
	)
	if !dnsSession {
		var err error
		conn, remote, err = h.dial.dialTarget(ctx, "udp", target)
		if err != nil {
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

type udpSession struct {
	// conn 与 connRoute 只在 installUpstream 的同一个临界区里一起替换、只在
	// closeUpstream 里一起清空，"连接已换、路由还是旧的"这种中间态不存在。
	conn      net.Conn
	remote    string
	connRoute *dnsRoute
	target    string

	dr         *crypto.DecryptedReader
	s2c        shaper.Shaper
	cancelRead func()
	// ctx 让"客户端已断开"能中止进行中的拨号，而不是白等到拨号超时。
	ctx         context.Context
	idleTimeout time.Duration
	nextProxy   *nextproxy.NextProxy
	dial        dialer
	dns         dnsState

	mu sync.Mutex

	done chan struct{}
	// closed 让读取侧区分"会话主动收尾"与目标侧真实故障：前者必然产生
	// read deadline exceeded 或 closed network connection，不能按故障记录。
	closed    chan struct{}
	closeOnce sync.Once
	// close 会等这些读取 goroutine 退出后才返回；Add 与 Wait 都只在主 goroutine 上。
	readers       sync.WaitGroup
	readerRunning bool
	resultCh      chan udpDatagram

	transferred int64
}

type udpSessionConfig struct {
	conn        net.Conn
	remote      string
	target      string
	dnsSession  bool
	dr          *crypto.DecryptedReader
	s2c         shaper.Shaper
	cancelRead  func()
	ctx         context.Context
	idleTimeout time.Duration
	nextProxy   *nextproxy.NextProxy
	route       dnsRouter
	dial        dialer
}

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

func (s *udpSession) upstream() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

func (s *udpSession) upstreamRoute() (dnsRoute, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil || s.connRoute == nil {
		return dnsRouteDirect, false
	}
	return *s.connRoute, true
}

// installUpstream 安装连接、远端地址与路由，返回被替换掉的旧连接，由调用方在锁外
// 关闭。watch 为真时必须为新连接补一个 reader；重复登记会让同一条连接被读两次。
func (s *udpSession) installUpstream(conn net.Conn, remote string, route dnsRoute, watch bool) net.Conn {
	s.mu.Lock()
	old := s.conn
	s.conn = conn
	s.remote = remote
	s.connRoute = &route
	s.mu.Unlock()
	if watch {
		s.startUpstreamReader(conn)
	}
	return old
}

func (s *udpSession) closeUpstream() {
	s.mu.Lock()
	conn := s.conn
	s.conn = nil
	s.connRoute = nil
	s.mu.Unlock()
	if conn != nil {
		conn.Close() //nolint:errcheck
	}
}

// conn 是产生该结果的出站连接：读取 goroutine 与重绑并发，旧连接报的错不能
// 结束新连接仍健康的会话。
type udpDatagram struct {
	conn    net.Conn
	payload []byte
	err     error
}

func (s *udpSession) run() (out streamResult) {
	defer func() {
		s.close()
		s.mu.Lock()
		out.Remote = s.remote
		s.mu.Unlock()
		out.Bytes = s.transferred
	}()

	s.readerRunning = true
	if conn := s.upstream(); conn != nil {
		s.startUpstreamReader(conn)
	}

	frameCh := make(chan udpFrameResult, 1)
	s.readers.Go(func() { s.readClientFrames(frameCh) })

	idle := time.NewTimer(s.idleTimeout)
	defer idle.Stop()

	// 空闲计时器只触发一次且触发分支直接返回，收尾无需排空 timer.C。
	idleC := idle.C

	for {
		select {
		case <-s.done:
			return streamResult{}
		case res := <-s.resultCh:
			if res.err != nil {
				// 检查与送达之间可能发生重绑，旧连接的错误不能结束新连接的会话。
				if res.conn != nil && res.conn != s.upstream() {
					continue
				}
				return streamResult{Err: s.targetReadError(res.err)}
			}
			s.transferred += int64(len(res.payload))
			// 只有发出过 DNS 查询的会话才解析：UDP 主力是 QUIC，逐报文解析约
			// 350ns/240B，随吞吐线性放大。
			if s.dns.intercept {
				s.learnFromDNS(res.payload)
			}
			// 这里不复制的前提是 shaper 对 DATAGRAM 恒不归还载荷（putPayload 仅对
			// FrameCOVER 为真），改成"归还任何池化载荷"会立即变成跨流数据污染。
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
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(s.idleTimeout)
			idleC = idle.C
		case <-idleC:
			return streamResult{TimedOut: true}
		}
	}
}

func (s *udpSession) observeClientFrame(f protocol.Frame) (alive bool, err error) {
	if f.Type != protocol.FrameDATAGRAM || len(f.Payload) == 0 {
		switch f.Type {
		case protocol.FrameFIN, protocol.FrameRST:
			return false, nil
		default:
			return true, nil
		}
	}

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

// DNS 会话的首条查询到这里才真正拨号；重拨失败即结束会话，客户端会重试。
func (s *udpSession) upstreamOrDial() (net.Conn, error) {
	conn := s.upstream()
	if conn != nil {
		return conn, nil
	}
	// 首帧不是合法查询时 routeSel 仍是零值（直连兜底），真正的查询随后会因与
	// connRoute 不一致而重绑；其他会话按目标一次性判定。
	route := dnsRouteDirect
	if s.dns.enabled && s.dns.router != nil {
		route = s.dns.routeSel
	} else if !s.dns.enabled {
		route = s.targetRoute()
	}
	if err := s.openUpstream(s.ctx, s.dns.dialDomain, route); err != nil {
		return nil, err
	}
	conn = s.upstream()
	if conn == nil {
		return nil, errors.New("udp upstream not established")
	}
	return conn, nil
}

// 连接必须由参数传入，不能从 s.upstream() 取：reader 在 go 之后、首次执行之前
// 碰上重绑会读到新连接，新连接因此有两个 reader，旧连接上的在飞应答随之丢失。
func (s *udpSession) startUpstreamReader(conn net.Conn) {
	s.readers.Go(func() { s.readFromTarget(conn) })
}

// 只读参数里的这条连接。回传遵守 done，会话收尾后不会卡在向无人接收的通道发送上。
func (s *udpSession) readFromTarget(conn net.Conn) {
	buf := bytespool.Get(udpBufSize)
	defer bytespool.MustPut(buf)
	// 读满整个池档位才能判断数据报是否被截断。
	readBuf := buf[:cap(buf)]

	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.idleTimeout))
		n, err := conn.Read(readBuf)
		if err != nil {
			if conn != s.upstream() {
				// 连接已被重绑替换，错误是拆连接的预期结果。
				return
			}
			if protocol.IsUDPMessageTooLong(err) {
				log.Warn("[UDP] dropping oversized datagram", "err", err)
				continue
			}
			s.sendResult(udpDatagram{conn: conn, err: err})
			return
		}
		if n > udpBufSize {
			log.Warn("[UDP] dropping oversized datagram", "n", n,
				"limit", udpBufSize, "truncated", n == len(readBuf))
			continue
		}
		payload := append([]byte(nil), readBuf[:n]...)
		if !s.sendResult(udpDatagram{conn: conn, payload: payload}) {
			return
		}
	}
}

func (s *udpSession) sendResult(d udpDatagram) bool {
	select {
	case s.resultCh <- d:
		return true
	case <-s.done:
		return false
	}
}

// 读取截止时间与连接关闭都是会话结束的正常路径，返回 io.EOF；真实故障原样返回。
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
		return io.EOF
	default:
	}
	return err
}

type udpFrameResult struct {
	frame protocol.Frame
	err   error
}

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

// 提前读取截止时间唤醒阻塞中的 reader，并等读取 goroutine 真正退出后才返回。
// 不能从被它等待的读取 goroutine 内部调用，否则死锁。
func (s *udpSession) close() {
	if s.done == nil {
		return
	}
	s.closeOnce.Do(func() {
		close(s.done)
		if s.cancelRead != nil {
			s.cancelRead()
		}
		if conn := s.upstream(); conn != nil {
			_ = conn.SetReadDeadline(time.Now())
		}
		s.closeUpstream()
		close(s.closed)
	})
	s.readers.Wait()
}
