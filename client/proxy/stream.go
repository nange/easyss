package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/relay"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
	"github.com/nange/easyss/v3/util/bytespool"
)

var ErrStreamIdleTimeout = errors.New("stream idle timeout")

var ErrStreamReset = errors.New("stream reset by peer")

// ErrServerRejectedHandshake 表示服务器以非加密载荷应答了引导（通常是握手解密
// 失败后的伪装 fallback 页面），即握手在任何会话记录交换之前就被拒绝。常见原因：
// master key 不匹配。
var ErrServerRejectedHandshake = errors.New("handshake rejected by server")

var errLocalConnClosed = errors.New("local connection closed")

type StreamHandler struct {
	transport         transport.Transport
	masterKey         []byte
	shaperCfg         shaper.Config
	streamIdleTimeout time.Duration
	// drainIdle 限制一条流在即将被驱逐（到期/降级）的 slot 上可保持空闲的时长，
	// 超过后中继提前关闭它；0 使用默认值 config.ExpiringStreamDrainIdle。它不作为
	// 用户配置项暴露——保留为字段是为了让测试可以用较短的时长来验证 drain 行为。
	drainIdle time.Duration
}

func NewStreamHandler(tr transport.Transport, masterKey []byte, shaperCfg shaper.Config, streamIdleTimeout time.Duration) *StreamHandler {
	if streamIdleTimeout <= 0 {
		streamIdleTimeout = config.DefaultStreamIdleTimeout
	}
	return &StreamHandler{
		transport:         tr,
		masterKey:         masterKey,
		shaperCfg:         shaperCfg,
		streamIdleTimeout: streamIdleTimeout,
	}
}

func (h *StreamHandler) Transport() transport.Transport {
	return h.transport
}

func (h *StreamHandler) OpenTCPStream(ctx context.Context, target string, method protocol.Method, localConn net.Conn) error {
	stats.RecordTCPConnection()
	return h.openStream(ctx, config.EndpointTCP, protocol.ProtoTCP, target, method, localConn)
}

func (h *StreamHandler) OpenICMPStream(ctx context.Context, target string, echoPayload []byte, method protocol.Method) ([]byte, error) {
	return h.icmpStream(ctx, config.EndpointICMP, protocol.ProtoICMP, target, echoPayload, method)
}

type bootstrapSession struct {
	stream transport.Stream
	sk     *crypto.StreamKeys
	salt   []byte
}

// 引导阶段的自愈参数。它们刻意是包级变量（而非常量），使测试可以把窗口缩短到
// 毫秒级；生产路径只读。
//
//   - bootstrapResponseTimeout：写完引导记录后等待"服务端做了什么回应"的有界窗口。
//     健康路径的响应头 ≈ 1 个路径 RTT，因此 4s 覆盖 RTT ≤ ~1s 的链路，又远小于
//     中继空闲超时（120s）——判死不再依赖后者。
//   - bootstrapLivenessTimeout：窗口到点后，在同一条连接上做一次存活探测的预算。
//     探测用来把"连接已死"与"服务端还在解析目标域名/链路很慢"区分开，因此窗口
//     可以取得小而不误伤慢服务端。
//   - bootstrapSettleTimeout：判死重试前等待本流 RoundTrip 收敛的上限，使
//     CloseIdle() 能可靠地把这条连接从 net/http 的池里摘掉（见 settleDeadStream）。
//     正常在微秒级返回，这个上限只是防御性的。
//
// bootstrapMaxAttempts 是"应用尚未收到任何数据"这一阶段允许的总尝试次数：第 1 次
// 通常踩在死连接上、第 2 次在判死路径（失效 + settle + 丢弃空闲连接）之后必然拿到
// 新连接；第 3 次留给"网络正在切换中"的抖动。每次尝试都重新生成 salt，服务端的
// 重放保护不会把重试当作重放（对它就是一条新流）。
const bootstrapMaxAttempts = 3

var (
	bootstrapResponseTimeout = 4 * time.Second
	bootstrapLivenessTimeout = 2 * time.Second
	bootstrapSettleTimeout   = 100 * time.Millisecond
)

func (h *StreamHandler) openAndBootstrap(ctx context.Context, endpoint string, proto protocol.Proto, target string, method protocol.Method, extraFrames []protocol.Frame) (*bootstrapSession, error) {
	hsFrame := protocol.NewFrameHANDSHAKE(protocol.Handshake{
		Version: protocol.Version3,
		Proto:   proto,
		Method:  method,
		Target:  target,
	})
	frames := append([]protocol.Frame{hsFrame}, extraFrames...)

	// 添加随机填充以隐藏引导记录中的目标主机名长度。否则，第一条记录的密文长度
	// 会直接与 len(target) 相关。
	if padFrame, ok := shaper.BuildPaddingFrame(encodedLen(frames)); ok {
		frames = append(frames, padFrame)
	}

	plaintext := protocol.EncodeFrames(frames)

	var lastErr error
	for attempt := 1; attempt <= bootstrapMaxAttempts; attempt++ {
		salt, err := crypto.GenerateSalt()
		if err != nil {
			return nil, fmt.Errorf("generate salt: %w", err)
		}
		saltB64 := base64.RawURLEncoding.EncodeToString(salt)

		stream, err := h.transport.Open(ctx, transport.OpenRequest{
			Endpoint:     endpoint,
			Salt:         saltB64,
			HighPriority: isInteractivePort(target),
			Target:       target,
		})
		if err != nil {
			return nil, fmt.Errorf("transport open: %w", err)
		}

		sk, err := crypto.NewStreamKeys(h.masterKey, salt, endpoint)
		if err != nil {
			stream.Close() //nolint:errcheck
			return nil, fmt.Errorf("stream keys: %w", err)
		}

		bootstrapWriter, err := sk.BootstrapWriter(stream)
		if err != nil {
			stream.Close() //nolint:errcheck
			return nil, fmt.Errorf("bootstrap writer: %w", err)
		}

		if err := bootstrapWriter.WriteRecord(plaintext); err != nil {
			stream.Close() //nolint:errcheck
			lastErr = fmt.Errorf("write handshake: %w", err)
			// 写失败说明管道已被 RoundTrip 的错误关闭，即连接在写入阶段就坏了。
			// 只有这一种错误值得换连接重试（其它写入错误是确定性的，重试无用）。
			if attempt < bootstrapMaxAttempts && errors.Is(err, io.ErrClosedPipe) {
				log.Debug("[STREAM] bootstrap write failed, retrying on a new connection",
					"attempt", attempt, "target", target, "err", err)
				// 等本流收敛并丢掉其余空闲连接：它们多半也绑在旧网络上，否则
				// 后续请求会逐个再踩一次死连接。判死瞬间做这件事，而不是等
				// 240s 的池级回收（见 settleDeadStream 对顺序的说明）。
				settleDeadStream(stream)
				h.transport.CloseIdle()
				continue
			}
			return nil, lastErr
		}
		bootstrapWriter.Flush()

		// 记录引导记录离开客户端的时刻：服务器在拨号源站之前就以响应头应答，
		// 因此传输层可在其到达时记录纯 client<->server 路径的 RTT
		// （参见 transport.BootstrapSentMarker）。
		if m, ok := stream.(transport.BootstrapSentMarker); ok {
			m.MarkBootstrapSent()
		}

		err = h.awaitBootstrapResponse(ctx, stream)
		if err == nil {
			return &bootstrapSession{stream: stream, sk: sk, salt: salt}, nil
		}
		lastErr = err

		// 判死：失效这条连接（它仍承载着本流，http.Transport 的
		// CloseIdleConnections 关不掉它），并丢掉其余空闲连接。只作用于本次请求
		// 自己的连接，因此不会误杀刚重试建立的新连接。
		invalidateDeadStream(stream)
		_ = stream.Close()

		// 上层取消（核心停止、本地连接已断）：不重试，直接上报。
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt < bootstrapMaxAttempts {
			log.Debug("[STREAM] bootstrap timed out, retrying on a new connection",
				"attempt", attempt, "target", target, "err", lastErr)
			// 必须先等本流的 RoundTrip 收敛，再丢弃空闲连接（见 settleDeadStream）。
			settleDeadStream(stream)
			h.transport.CloseIdle()
			continue
		}
		return nil, lastErr
	}

	// 不可达：循环体内部总是会返回。
	return nil, lastErr
}

// awaitBootstrapResponse 在引导阶段用一个有界窗口等待服务端的回应，并在窗口
// 到点时用一次同连接探测区分"连接已死"与"服务端只是还没答复"（例如仍在解析
// 目标域名）。返回 nil 表示可以继续（响应已就绪，或判活确认连接仍然可往返）；
// 返回非 nil 表示这条连接应判死。
//
// 传输层未实现 transport.ResponseAwaiter 时不做任何等待，行为与既有实现完全一致。
//
// 状态清理的边界：这里只做"判死 + 重试"这类无状态动作，不触碰任何缓存、DNS
// 熔断、可达记录或 pin——那些只影响最优性，不出现在可用性路径上。
func (h *StreamHandler) awaitBootstrapResponse(ctx context.Context, stream transport.Stream) error {
	ra, ok := stream.(transport.ResponseAwaiter)
	if !ok {
		return nil
	}

	waitCtx, cancel := context.WithTimeout(ctx, bootstrapResponseTimeout)
	err := ra.AwaitResponse(waitCtx)
	cancel()

	if err == nil {
		// 响应已就绪：成功或服务端拒绝（非 200 已被传输层转成
		// HandshakeRejectedError）。拒绝的分类交给首次 Read，不应在这里重试。
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		// 传输层错误：连接在写入阶段或响应阶段就坏了，立即换连接，不必等满窗口。
		return err
	}

	// 窗口到点：先问"这条连接还能不能往返"。服务端在解析目标域名之后才提交
	// 响应头，因此"响应头迟到"不等于"连接已死"；判活成功就继续等（无回归）。
	if cl, ok := stream.(transport.ConnLiveness); ok {
		liveCtx, cancelLive := context.WithTimeout(ctx, bootstrapLivenessTimeout)
		alive, known := cl.ConnAlive(liveCtx)
		cancelLive()
		if known && alive {
			log.Debug("[STREAM] bootstrap response late but connection is alive, keep waiting",
				"response_timeout", bootstrapResponseTimeout)
			return nil
		}
	}
	return err
}

// invalidateDeadStream 让传输层强制关闭本流所在的那条底层连接：判死重试必须
// 换连接，而 http.Transport 的 CloseIdleConnections 不会关闭承载活跃流的连接。
// 未实现 transport.ConnInvalidator 的传输层（测试桩、其他实现）保持现状。
func invalidateDeadStream(stream transport.Stream) {
	if inv, ok := stream.(transport.ConnInvalidator); ok {
		inv.InvalidateConn()
	}
}

// settleDeadStream 用有界窗口等待一条已关闭的流的 RoundTrip 收敛。
//
// 判死路径必须在 CloseIdle() 之前等这一步：InvalidateConn 关掉底层连接后，
// net/http 的读循环是异步感知并回收它的；在那之前这条连接仍被本流"占用"，
// 而 CloseIdleConnections 只回收空闲连接——于是下一次 Open 会把这条正在死去的
// 连接再次交付出来，引导记录写入立即以 io.ErrClosedPipe 失败，白白消耗一次尝试
// （判死即换连接的核心保证也就不严格成立）。等本流的 RoundTrip 返回后，连接才
// 真正转为空闲，CloseIdle() 能可靠地把它从池里摘掉。
//
// 实测这一步在本地约 25µs；未实现 transport.ResponseAwaiter 的传输层没有这个
// 问题（也不会被等待）。
func settleDeadStream(stream transport.Stream) {
	ra, ok := stream.(transport.ResponseAwaiter)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapSettleTimeout)
	defer cancel()
	_ = ra.AwaitResponse(ctx)
}

// classifyFirstReadError 将由非加密服务器响应（例如握手被拒绝后的 fallback 页面）
// 引起的首条记录读取失败映射为带诊断提示的 ErrServerRejectedHandshake。只有
// 第一次读取会被分类：流中途的失败意味着真正的流损坏，而不是握手被拒绝。
func classifyFirstReadError(err error) error {
	if err == nil || errors.Is(err, ErrServerRejectedHandshake) {
		return err
	}
	if transport.IsHandshakeRejected(err) {
		return err
	}
	msg := err.Error()
	for _, pat := range []string{"crypto: ciphertext exceeds max", "crypto: zero-length ciphertext", "crypto: decrypt record"} {
		if strings.Contains(msg, pat) {
			return fmt.Errorf("%w: server returned a non-encrypted payload (check master_key or server config)", ErrServerRejectedHandshake)
		}
	}
	return err
}

func (h *StreamHandler) icmpStream(ctx context.Context, endpoint string, proto protocol.Proto, target string, echoPayload []byte, method protocol.Method) ([]byte, error) {
	log.Debug("[STREAM] icmp open", "endpoint", endpoint, "target", target)

	s, err := h.newSession(ctx, endpoint, proto, target, method,
		[]protocol.Frame{protocol.NewFrameDATA(echoPayload)}, 0)
	if err != nil {
		log.Error("[STREAM] icmp bootstrap", "target", target, "err", err)
		return nil, err
	}
	log.Debug("[STREAM] merged ICMP echo payload into bootstrap record", "bytes", len(echoPayload))
	defer s.stream.Close() //nolint:errcheck
	// 此路径只接收：echo 载荷已随引导记录发送，tx 永远不会被写入。它仍然持有
	// 一个池化的 64KB 记录缓冲区（shaper.New 从 bytespool 取出，只有 Close 会
	// 归还）和一个 cover 注入器，因此必须关闭。它声明在 stream 的 defer 之后，
	// 因此会先执行（LIFO），避免向已关闭的流做冲刷。
	defer s.tx.Close() //nolint:errcheck

	frame, err := s.rx.ReadFrame()
	err = classifyFirstReadError(err)
	if err != nil {
		log.Error("[STREAM] icmp read reply", "target", target, "err", err)
		return nil, fmt.Errorf("read first reply frame: %w", err)
	}

	if frame.Type == protocol.FrameRST {
		log.Error("[STREAM] icmp rejected", "target", target)
		return nil, fmt.Errorf("icmp rejected by server")
	}

	if frame.Type != protocol.FrameDATA {
		return nil, fmt.Errorf("expected DATA frame, got %d", frame.Type)
	}

	return frame.Payload, nil
}

// session 汇集了引导握手之后每种协议所需的东西：传输流、整形 c2s 写入器和
// s2c 帧读取器。将它们一起构建（参见 newSession）使写入/读取对保持在同一个
// 地方，这样 TCP、UDP 和 ICMP 在会话协商方式上不会发生偏离。
type session struct {
	stream transport.Stream
	tx     shaper.Shaper
	rx     *crypto.DecryptedReader
}

// newSession 打开流，发送引导记录（握手帧加上合并进来的任何帧），并派生会话的
// 读取/写入对。
// batchWindowMS 大于 0 时覆盖配置的 shaper 批处理窗口（UDP 使用较短的 1ms
// 窗口，使数据报突发合并进单条记录）。
func (h *StreamHandler) newSession(ctx context.Context, endpoint string, proto protocol.Proto, target string, method protocol.Method, extraFrames []protocol.Frame, batchWindowMS int) (*session, error) {
	bs, err := h.openAndBootstrap(ctx, endpoint, proto, target, method, extraFrames)
	if err != nil {
		return nil, err
	}
	stream := bs.stream

	txWriter, err := bs.sk.NewWriter(stream, crypto.DirC2S, method)
	if err != nil {
		stream.Close() //nolint:errcheck
		return nil, fmt.Errorf("c2s session writer: %w", err)
	}

	shaperCfg := h.shaperCfg
	if batchWindowMS > 0 {
		shaperCfg.BatchWindowMS = batchWindowMS
	}
	tx := shaper.New(txWriter, shaperCfg)

	rx, err := bs.sk.NewReader(stream, crypto.DirS2C, method)
	if err != nil {
		_ = tx.Close()
		stream.Close() //nolint:errcheck
		return nil, fmt.Errorf("s2c session reader: %w", err)
	}

	return &session{stream: stream, tx: tx, rx: rx}, nil
}

func (h *StreamHandler) openStream(ctx context.Context, endpoint string, proto protocol.Proto, target string, method protocol.Method, localConn net.Conn) error {
	log.Debug("[STREAM] opening", "endpoint", endpoint, "target", target)

	var extraFrames []protocol.Frame
	if localConn != nil {
		_ = localConn.SetReadDeadline(time.Now().Add(8 * time.Millisecond))
		buf := bytespool.Get(config.TCPStreamBufferSize)
		n, rErr := localConn.Read(buf)
		_ = localConn.SetReadDeadline(time.Time{})
		if n > 0 {
			extraFrames = []protocol.Frame{protocol.NewFrameDATA(buf[:n])}
			log.Debug("[STREAM] merged first DATA into bootstrap record", "bytes", n, "read_err", rErr)
		}
		bytespool.MustPut(buf)
	}

	s, err := h.newSession(ctx, endpoint, proto, target, method, extraFrames, 0)
	if err != nil {
		log.Error("[STREAM] bootstrap", "endpoint", endpoint, "target", target, "err", err)
		return err
	}
	defer s.tx.Close() //nolint:errcheck
	log.Debug("[STREAM] handshake sent", "target", target)

	err = h.relay(target, localConn, s.tx, s.rx, s.stream)
	log.Debug("[STREAM] relay finished", "endpoint", endpoint, "target", target, "err", err)
	return err
}

func (h *StreamHandler) relay(target string, localConn net.Conn, tx shaper.Shaper, rx *crypto.DecryptedReader, stream transport.Stream) error {
	m := stats.NewStreamMeter("client", target)
	defer m.Close()

	closeAll := relay.CloseBoth(stream, localConn)

	// 驱逐即将到来的 slot 上的空闲流：一旦 slot 处于到期（连接超过时长/字节上限）
	// 或降级（确认变慢）状态，空闲达到 ExpiringStreamDrainIdle 的流就是残留的
	// keep-alive 或半关闭连接——提前关闭它，使 slot 的轮换/退役不必等到完整的
	// 空闲超时。活跃流（有数据流动）会重置中继的空闲时钟，永远不会被 drain。
	// 传输层未实现 SlotDrainingStream 的流保持原有行为。
	var drainWhen func() bool
	if ds, ok := stream.(transport.SlotDrainingStream); ok {
		drainWhen = ds.SlotDraining
	}
	drainIdle := h.drainIdle
	if drainIdle <= 0 {
		drainIdle = config.ExpiringStreamDrainIdle
	}

	result := relay.BidirectionalWithDrain(h.streamIdleTimeout, drainWhen, drainIdle, closeAll,
		func(signal func()) error { return h.copyLocalToRemote(localConn, tx, signal) },
		func(signal func()) error { return h.copyRemoteToLocal(rx, localConn, signal, m) },
	)

	if result.Drained {
		stats.RecordStreamDrained()
		log.Debug("[STREAM] drained idle stream on slot due for eviction", "target", target)
		return fmt.Errorf("%w: drained (slot due for eviction)", ErrStreamIdleTimeout)
	}

	if result.TimedOut {
		log.Debug("[STREAM] idle timeout", "timeout", h.streamIdleTimeout)
		return fmt.Errorf("%w after %v", ErrStreamIdleTimeout, h.streamIdleTimeout)
	}

	if result.Err != nil && !errors.Is(result.Err, errLocalConnClosed) && !errors.Is(result.Err, io.ErrClosedPipe) {
		log.Debug("[STREAM] relay copy error", "err", result.Err)
		return result.Err
	}
	return nil
}

func (h *StreamHandler) copyLocalToRemote(src net.Conn, tx shaper.Shaper, signalActivity func()) error {
	buf := bytespool.Get(config.TCPStreamBufferSize)
	defer bytespool.MustPut(buf)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			signalActivity()
			stats.RecordRawBytesSent(n)
			if pErr := tx.PushData(buf[:n]); pErr != nil {
				_ = tx.Flush()
				if errors.Is(pErr, io.ErrClosedPipe) {
					return nil
				}
				return pErr
			}
		}
		if err != nil {
			finFrame := protocol.NewFrameFIN()
			_ = tx.PushFrame(finFrame)
			_ = tx.Flush()
			signalActivity()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if isLocalConnClosedError(err) {
				log.Debug("[STREAM] local connection closed", "err", err)
				return errLocalConnClosed
			}
			log.Debug("[STREAM] local read error", "err", err)
			return err
		}
	}
}

func (h *StreamHandler) copyRemoteToLocal(rx *crypto.DecryptedReader, dst net.Conn, signalActivity func(), m *stats.StreamMeter) error {
	type frameItem struct {
		data []byte
		fin  bool
		rst  bool
	}

	ch := make(chan frameItem, 64)
	readDone := make(chan error, 1)
	done := make(chan struct{})
	defer close(done)

	go func() {
		defer close(ch)
		first := true
		for {
			frame, err := rx.ReadFrame()
			if first {
				first = false
				err = classifyFirstReadError(err)
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					readDone <- nil
				} else {
					log.Debug("[STREAM] remote read error", "err", err)
					readDone <- err
				}
				return
			}

			switch frame.Type {
			case protocol.FrameDATA:
				signalActivity()
				if len(frame.Payload) > 0 {
					select {
					case ch <- frameItem{data: frame.Payload}:
					case <-done:
						readDone <- nil
						return
					}
				}
			case protocol.FrameFIN:
				signalActivity()
				select {
				case ch <- frameItem{fin: true}:
				case <-done:
				}
				readDone <- nil
				return
			case protocol.FrameRST:
				select {
				case ch <- frameItem{rst: true}:
				case <-done:
				}
				readDone <- nil
				return
			case protocol.FramePADDING, protocol.FrameCOVER:
				continue
			}
		}
	}()

	for item := range ch {
		if item.rst {
			return fmt.Errorf("%w", ErrStreamReset)
		}
		if item.fin {
			return nil
		}
		m.SetState("write_local")
		if _, wErr := dst.Write(item.data); wErr != nil {
			if isLocalConnClosedError(wErr) {
				log.Debug("[STREAM] local connection closed", "err", wErr)
				return errLocalConnClosed
			}
			return wErr
		}
		stats.RecordRawBytesRecv(len(item.data))
		m.Add(len(item.data), "read_remote")
	}

	return <-readDone
}

// isTransientStreamError 报告流失败是否是瞬时或预期的（空闲超时、对端重置、
// 握手被拒绝、HTTP/2 连接断开、流已关闭）。这类失败在连接死亡或服务器拒绝时
// 常会同时命中许多流，应以 Debug 级别记录，而不是逐流刷满 Error 日志。
func isTransientStreamError(err error) bool {
	if errors.Is(err, ErrStreamIdleTimeout) || errors.Is(err, ErrStreamReset) {
		return true
	}
	if errors.Is(err, ErrServerRejectedHandshake) || transport.IsHandshakeRejected(err) {
		return true
	}
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "client connection lost") ||
		strings.Contains(msg, "http2: stream closed") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection was aborted")
}

// isLocalConnClosedError 报告 err 是否表示本地连接已消失（我们自己关闭了它，
// 或对端拒绝/重置了它），而不是流级别的失败。它刻意不把 "connection reset by
// peer" 归类进去：该情况由 isTransientStreamError 负责，如果两者都归类同一个
// 字符串，同一个失败会因先执行哪个检查而被报告成两种不同的东西。
func isLocalConnClosedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "forcibly closed by the remote host") ||
		strings.Contains(msg, "software caused connection abort") ||
		strings.Contains(msg, "connection was aborted") ||
		strings.Contains(msg, "broken pipe")
}

// encodedLen 返回一组帧的总线上大小（头部 + 载荷）。
func encodedLen(frames []protocol.Frame) int {
	total := 0
	for _, f := range frames {
		total += f.EncodedLen()
	}
	return total
}

type UDPExchange struct {
	stream    transport.Stream
	tx        shaper.Shaper
	reader    *crypto.DecryptedReader
	target    string
	lastSeen  atomic.Int64 // UnixNano，由 Send/Receive 写入，由 LastSeen 读取
	firstRead atomic.Bool  // 在首次 ReadFrame 时置位，启用拒绝分类
	mu        sync.Mutex
	closeOnce sync.Once
}

func (h *StreamHandler) OpenUDPExchange(ctx context.Context, target string, method protocol.Method, firstPayload []byte) (*UDPExchange, error) {
	stats.RecordUDPAssociation()
	log.Debug("[UDP_EXCHANGE] opening", "target", target)

	// 仅在合并后的明文保证能放进 MaxPlainRecordSize 时，才把第一个数据报合并进
	// 引导记录：HANDSHAKE 帧（3 + 3 + len(target)）加上 DATAGRAM 帧头（3）再
	// 加上载荷，填充会自行适应（记录将要溢出时 BuildPaddingFrame 会退避）。
	// 过大的首个数据报（例如巨型包加上很长的目标名）改为在握手之后立即发送，
	// 而不是让整个交换失败。
	var extraFrames []protocol.Frame
	mergeFirst := false
	if len(firstPayload) > 0 {
		if len(firstPayload)+len(target)+9 <= protocol.MaxPlainRecordSize {
			mergeFirst = true
			extraFrames = []protocol.Frame{protocol.NewFrameDATAGRAM(firstPayload)}
			log.Debug("[UDP_EXCHANGE] merged first DATAGRAM into bootstrap record", "bytes", len(firstPayload))
		} else {
			log.Debug("[UDP_EXCHANGE] first DATAGRAM too large for bootstrap, sending after handshake", "bytes", len(firstPayload))
		}
	}

	// UDP 使用较短的 1ms 批处理窗口而不是每个数据报强制冲刷：数据报突发会被
	// 合并进单条加密记录，同时由空闲触发的定时器把稀疏流量（DNS、游戏）的交互
	// 延迟限制在约 1ms。
	s, err := h.newSession(ctx, config.EndpointUDP, protocol.ProtoUDP, target, method, extraFrames, 1)
	if err != nil {
		log.Error("[UDP_EXCHANGE] bootstrap", "target", target, "err", err)
		return nil, err
	}

	log.Debug("[UDP_EXCHANGE] opened", "target", target)
	ue := &UDPExchange{
		stream: s.stream,
		tx:     s.tx,
		reader: s.rx,
		target: target,
	}
	ue.lastSeen.Store(time.Now().UnixNano())

	if len(firstPayload) > 0 && !mergeFirst {
		if err := ue.Send(firstPayload); err != nil {
			ue.Close() //nolint:errcheck
			return nil, fmt.Errorf("send first datagram: %w", err)
		}
	}
	return ue, nil
}

func (ue *UDPExchange) Send(data []byte) error {
	ue.mu.Lock()
	defer ue.mu.Unlock()
	ue.lastSeen.Store(time.Now().UnixNano())
	frame := protocol.NewFrameDATAGRAM(data)
	return ue.tx.PushFrame(frame)
}

func (ue *UDPExchange) Receive() ([]byte, error) {
	for {
		frame, err := ue.reader.ReadFrame()
		if ue.firstRead.CompareAndSwap(false, true) {
			err = classifyFirstReadError(err)
		}
		if err != nil {
			return nil, err
		}
		ue.lastSeen.Store(time.Now().UnixNano())
		switch frame.Type {
		case protocol.FrameDATAGRAM:
			return frame.Payload, nil
		case protocol.FrameFIN:
			return nil, io.EOF
		case protocol.FrameRST:
			return nil, fmt.Errorf("udp stream reset")
		case protocol.FramePADDING, protocol.FrameCOVER:
			continue
		default:
			return nil, fmt.Errorf("unexpected frame type: %d", frame.Type)
		}
	}
}

// Close 终止交换。它在关闭 shaper 与流之前发送一个 FIN 帧，使服务器能立即回收
// 其 UDP 关联，而不是等待空闲超时。FIN 必须在 tx.Close 之前推入：shaper 一旦
// 开始关闭，PushFrame 就会丢弃帧。并发的 Close 调用方（空闲清理、receiveLoop
// 退出、发送失败）通过 closeOnce 和 mu 串行化。FIN 的投递是尽力而为；如果失败，
// 服务器会回退到其空闲超时。
func (ue *UDPExchange) Close() error {
	ue.closeOnce.Do(func() {
		ue.mu.Lock()
		defer ue.mu.Unlock()
		if ue.tx != nil {
			_ = ue.tx.PushFrame(protocol.NewFrameFIN())
			_ = ue.tx.Flush()
			_ = ue.tx.Close()
		}
		_ = ue.stream.Close()
	})
	return nil
}

func (ue *UDPExchange) LastSeen() time.Time {
	return time.Unix(0, ue.lastSeen.Load())
}

func isInteractivePort(target string) bool {
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	switch port {
	case "22", "80", "443", "8080", "8443":
		return true
	}
	return false
}
