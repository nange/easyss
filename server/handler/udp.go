package handler

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/util/bytespool"
)

const udpBufSize = protocol.MaxUDPDataSize

type udpHandler struct {
	idleTimeout time.Duration
	// nextProxy 在这里单独保存（而不仅存在于 dial 内部），因为只有 UDP
	// 会在数据报流上用它进行 DNS 应答学习，与当前目标是否经由它路由无关。
	nextProxy *nextproxy.NextProxy
	dial      dialer
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
			return np.EnableUDP() && np.ShouldProxy(target)
		},
		direct: func(ctx context.Context, network, target string) (net.Conn, error) {
			return dialOutbound(ctx, directDialer, network, target)
		},
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

	conn, remote, err := h.dial.dialTarget(ctx, "udp", target)
	if err != nil {
		log.Error("[UDP] dial target failed", "target", target, "err", err)
		sendRST(s2c)
		return streamResult{Err: err}
	}

	s := newUDPSession(udpSessionConfig{
		conn:        conn,
		remote:      remote,
		target:      target,
		dr:          dr,
		s2c:         s2c,
		cancelRead:  cancelRead,
		idleTimeout: h.idleTimeout,
		nextProxy:   h.nextProxy,
		shouldProxy: h.dial.shouldProxy,
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
	conn        net.Conn
	remote      string
	target      string
	dr          *crypto.DecryptedReader
	s2c         shaper.Shaper
	cancelRead  func()
	idleTimeout time.Duration
	nextProxy   *nextproxy.NextProxy
	shouldProxy func(target string) bool

	// done 是唯一的关闭信号：close 关闭它，两个读取 goroutine 都在发送
	// 结果之前检查它。
	done chan struct{}
	// closed 让读取侧能区分"会话主动收尾"与"目标侧真实故障"：
	// 前者必然产生 read deadline exceeded / closed network connection，
	// 不能按故障记录。它由 closeOnce 关闭，因此只会关闭一次。
	closed    chan struct{}
	closeOnce sync.Once
	// readers 跟踪两个读取 goroutine（目标侧与客户端帧侧）。close 会等待它们
	// 退出后返回，因此"会话结束后没有读取 goroutine 残留"是收尾的一部分，
	// 而不是一个只能靠 sleep 观察的猜测。
	readers sync.WaitGroup
	// resultCh 携带目标侧读到的每个数据报。
	resultCh chan udpDatagram
	// dns 是完全由主 goroutine 私有的学习状态（读取侧只回传已解析的报文）。
	dns dnsLearnHint

	// transferred 是服务端到客户端方向已推送的载荷字节数。它只由主
	// goroutine 写入（读取侧经 resultCh 回传后累加），因此没有并发访问。
	transferred int64
}

// udpSessionConfig 是 udpSession 的构造参数。
type udpSessionConfig struct {
	conn        net.Conn
	remote      string
	target      string
	dr          *crypto.DecryptedReader
	s2c         shaper.Shaper
	cancelRead  func()
	idleTimeout time.Duration
	nextProxy   *nextproxy.NextProxy
	shouldProxy func(target string) bool
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
		idleTimeout: cfg.idleTimeout,
		nextProxy:   cfg.nextProxy,
		shouldProxy: cfg.shouldProxy,
		done:        make(chan struct{}),
		closed:      make(chan struct{}),
		resultCh:    make(chan udpDatagram, 1),
	}
}

// udpDatagram 是读取 goroutine 回传给主 goroutine 的一个目标侧数据报。
// dnsMsg 非空表示该数据报已被识别为 DNS 应答（只解析一次）。
type udpDatagram struct {
	payload []byte
	dnsMsg  *dns.Msg
	err     error
}

// dnsLearnHint 是由主 goroutine 独占的学习状态：它在第一个客户端帧上判断
// 这是否是一次指向自定义域名的 DNS 查询，此后的 DNS 应答才允许被学习。
// 此前这个提示是一个传进读取 goroutine 的 *atomic.Bool，但它的写入点只在
// 主 goroutine，原子化掩盖了一个本可以用所有权划分说清的问题。
type dnsLearnHint struct {
	// checked 表示"第一个客户端帧"的判定已经完成（只判定一次）。
	checked bool
	// intercept 表示该会话确实发出过一次指向自定义域名的 DNS 查询。
	intercept bool
}

// run 驱动整个 UDP 会话，返回唯一的退出结果。
func (s *udpSession) run() (out streamResult) {
	// 收尾只有这一处：无论从哪个分支退出（FIN/RST、目标 EOF、错误、空闲超时），
	// 都在这里关闭目标连接、解除读取侧的阻塞、等待读取 goroutine 退出。
	defer func() {
		s.close()
		out.Remote = s.remote
		out.Bytes = s.transferred
	}()

	s.readers.Go(s.readFromTarget)

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
			s.learnFromDNS(res)
			if err := s.s2c.PushFrame(protocol.NewFrameDATAGRAM(res.payload)); err != nil {
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
	if !s.dns.checked {
		s.detectDNSQuery(f)
		s.dns.checked = true
	}
	switch f.Type {
	case protocol.FrameDATAGRAM:
		if len(f.Payload) > 0 {
			if _, err := s.conn.Write(f.Payload); err != nil {
				return false, err
			}
		}
		return true, nil
	case protocol.FrameFIN, protocol.FrameRST:
		return false, nil
	default:
		// PADDING/COVER 等填充帧不影响会话状态。
		return true, nil
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
		_ = s.conn.SetReadDeadline(time.Now())
		_ = s.conn.Close()
		close(s.closed)
	})
	s.readers.Wait()
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

// readFromTarget 是唯一读取目标连接的地方。它只读原始报文并（对疑似 DNS
// 报文）解析一次，随后把结果回传；是否学习、是否推送都由主 goroutine 决定。
// 回传（含错误）都遵守 done：会话一旦收尾，读取侧必须能立即退出，而不是
// 卡在向一个已经没有接收者的通道发送上——close 会等待这个 goroutine。
func (s *udpSession) readFromTarget() {
	buf := bytespool.Get(udpBufSize)
	defer bytespool.MustPut(buf)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(s.idleTimeout))
		n, err := s.conn.Read(buf)
		if err != nil {
			s.sendResult(udpDatagram{err: s.targetReadError(err)})
			return
		}
		payload := append([]byte(nil), buf[:n]...)
		if !s.sendResult(udpDatagram{payload: payload, dnsMsg: s.maybeDNS(payload)}) {
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
	log.Error("[UDP] read from target failed", "target", s.remote, "err", err)
	return err
}

// maybeDNS 解析一个疑似 DNS 报文；不是 DNS 应答时返回 nil。解析只在这里
// 发生，主 goroutine 复用同一份 *dns.Msg 做学习判定。
func (s *udpSession) maybeDNS(payload []byte) *dns.Msg {
	if s.nextProxy == nil || len(payload) == 0 {
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

// detectDNSQuery 在第一个客户端帧上判断它是否是一次指向自定义域名的 DNS
// 查询，并据此启用应答拦截（动态 IP 学习）。只检查一次：一个会话只承载
// 一次 DNS 查询的开端。
func (s *udpSession) detectDNSQuery(f protocol.Frame) {
	if s.nextProxy == nil || f.Type != protocol.FrameDATAGRAM || len(f.Payload) == 0 {
		return
	}
	msg := &dns.Msg{}
	if err := msg.Unpack(f.Payload); err != nil || !util.IsDNSRequest(msg) {
		return
	}
	s.dns.intercept = true
	domain := strings.TrimSuffix(msg.Question[0].Name, ".")
	viaNextProxy := s.shouldProxy != nil && s.shouldProxy(s.target)
	log.Info("[UDP_DNS]", "domain", domain, "target", s.target, "via_next_proxy", viaNextProxy)
}

// learnFromDNS 用指向自定义域名的 DNS 应答喂给 next proxy 的动态路由表
// （CNAME 目标与解析出的 IP）。只有会话确实发出过 DNS 查询时才学习。
func (s *udpSession) learnFromDNS(res udpDatagram) {
	if !s.dns.intercept || s.nextProxy == nil || res.dnsMsg == nil {
		return
	}
	domain := strings.TrimSuffix(res.dnsMsg.Question[0].Name, ".")
	if !s.nextProxy.IsCustomDomain(domain) {
		return
	}
	util.ForEachDNSAnswer(res.dnsMsg, func(kind, value string) {
		if kind == "CNAME" {
			s.nextProxy.AddDomain(value)
			return
		}
		s.nextProxy.AddIP(value)
	})
}

// udpFrameResult 是客户端帧读取 goroutine 回传的一个结果。
type udpFrameResult struct {
	frame protocol.Frame
	err   error
}
