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
	"github.com/nange/easyss/v3/util/netbuf"
)

var ErrStreamIdleTimeout = errors.New("stream idle timeout")

var ErrStreamReset = errors.New("stream reset by peer")

// 服务端以非加密载荷应答引导（通常是 fallback 页），多半是 master key 不匹配。
var ErrServerRejectedHandshake = errors.New("handshake rejected by server")

var errLocalConnClosed = errors.New("local connection closed")

// 没有 Close：transport 由 client.Client 持有并拆除，单条流/交换的资源由各自所有者释放。
type StreamHandler struct {
	transport         transport.Transport
	masterKey         []byte
	shaperCfg         shaper.Config
	streamIdleTimeout time.Duration
	// drainIdle 限制一条流在即将被驱逐的 slot 上可保持空闲的时长，0 用默认值。
	drainIdle time.Duration
}

func NewStreamHandler(tr transport.Transport, masterKey []byte, shaperCfg shaper.Config, timeouts config.Timeouts) *StreamHandler {
	return &StreamHandler{
		transport:         tr,
		masterKey:         masterKey,
		shaperCfg:         shaperCfg,
		streamIdleTimeout: timeouts.Normalize().StreamIdle,
	}
}

func (h *StreamHandler) Transport() transport.Transport {
	return h.transport
}

// streamRequest 是一条流的不可变请求。endpoint 与 proto 必须成对，由 tcp/udp/icmp
// 构造函数保证；frames 是合并进引导记录的首批帧（TCP 首批数据 / ICMP echo / UDP 首个数据报）。
type streamRequest struct {
	endpoint      string
	proto         protocol.Proto
	target        string
	method        protocol.Method
	frames        []protocol.Frame
	batchWindowMS int
}

func tcpStreamRequest(target string, method protocol.Method) streamRequest {
	return newStreamRequest(config.EndpointTCP, protocol.ProtoTCP, target, method)
}

func udpStreamRequest(target string, method protocol.Method) streamRequest {
	return newStreamRequest(config.EndpointUDP, protocol.ProtoUDP, target, method)
}

func icmpStreamRequest(target string, method protocol.Method) streamRequest {
	return newStreamRequest(config.EndpointICMP, protocol.ProtoICMP, target, method)
}

func newStreamRequest(endpoint string, proto protocol.Proto, target string, method protocol.Method) streamRequest {
	return streamRequest{endpoint: endpoint, proto: proto, target: target, method: method}
}

func (r streamRequest) withFrames(frames ...protocol.Frame) streamRequest {
	r.frames = frames
	return r
}

func (r streamRequest) withBatchWindow(ms int) streamRequest {
	r.batchWindowMS = ms
	return r
}

func (r streamRequest) firstPayloadBytes() int {
	if len(r.frames) == 0 {
		return 0
	}
	return len(r.frames[0].Payload)
}

func (h *StreamHandler) OpenTCPStream(ctx context.Context, target string, method protocol.Method, localConn net.Conn) error {
	stats.RecordTCPConnection()
	return h.openStream(ctx, tcpStreamRequest(target, method), localConn)
}

func (h *StreamHandler) OpenICMPStream(ctx context.Context, target string, echoPayload []byte, method protocol.Method) ([]byte, error) {
	req := icmpStreamRequest(target, method).withFrames(protocol.NewFrameDATA(echoPayload))
	return h.icmpStream(ctx, req)
}

type bootstrapSession struct {
	stream transport.Stream
	sk     *crypto.StreamKeys
	salt   []byte
}

// 自愈参数：超时窗口刻意是变量而非常量，测试能缩到毫秒级；liveness 探测区分"连接已死"与"服务端还在解析域名"。
const bootstrapMaxAttempts = 3

var (
	bootstrapResponseTimeout = 4 * time.Second
	bootstrapLivenessTimeout = 2 * time.Second
	bootstrapSettleTimeout   = 100 * time.Millisecond
)

// 手工拼装不经过整形器的预冲刷边界，必须自己校验额外帧的线上总长，保证明文能被 WriteRecord 接受。
func buildBootstrapPlaintext(req streamRequest) ([]byte, error) {
	hsFrame := protocol.NewFrameHANDSHAKE(protocol.Handshake{
		Version: protocol.Version3,
		Proto:   req.proto,
		Method:  req.method,
		Target:  req.target,
	})
	frames := append([]protocol.Frame{hsFrame}, req.frames...)

	// 先校验填充之前的长度：额外帧放不进一条记录时填充退避也救不回来。
	if size := encodedLen(frames); size > protocol.MaxWriteRecordPlaintext {
		return nil, fmt.Errorf("bootstrap record plaintext %d exceeds max %d bytes (target %q, %d extra frames)",
			size, protocol.MaxWriteRecordPlaintext, req.target, len(req.frames))
	}

	// 随机填充掩盖目标主机名长度：否则首条记录的密文长度会直接与 len(target) 相关。
	if padFrame, ok := shaper.BuildPaddingFrame(encodedLen(frames), protocol.MaxWriteRecordPlaintext); ok {
		frames = append(frames, padFrame)
	}

	return protocol.EncodeFrames(frames), nil
}

func (h *StreamHandler) openAndBootstrap(ctx context.Context, req streamRequest) (*bootstrapSession, error) {
	plaintext, err := buildBootstrapPlaintext(req)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for attempt := 1; attempt <= bootstrapMaxAttempts; attempt++ {
		salt, err := crypto.GenerateSalt()
		if err != nil {
			return nil, fmt.Errorf("generate salt: %w", err)
		}
		saltB64 := base64.RawURLEncoding.EncodeToString(salt)

		stream, err := h.transport.Open(ctx, transport.OpenRequest{
			Endpoint:     req.endpoint,
			Salt:         saltB64,
			HighPriority: isInteractivePort(req.target),
			Target:       req.target,
		})
		if err != nil {
			return nil, fmt.Errorf("transport open: %w", err)
		}

		sk, err := crypto.NewStreamKeys(h.masterKey, salt, req.endpoint)
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
			// 管道被关闭说明连接在写入阶段就坏了，只有这一种写入错误值得换连接重试。上层已取消
			// 时同样不重试：取消不是判死，也不该顺手丢弃连接池。
			if attempt < bootstrapMaxAttempts && errors.Is(err, io.ErrClosedPipe) && ctx.Err() == nil {
				log.Debug("[STREAM] bootstrap write failed, retrying on a new connection",
					"attempt", attempt, "target", req.target, "err", err)
				settleDeadStream(stream)
				h.transport.CloseIdle()
				continue
			}
			return nil, lastErr
		}
		bootstrapWriter.Flush()

		// 服务端在拨号源站之前就应答，传输层据此记录纯 client<->server 路径的 RTT。
		if m, ok := stream.(transport.BootstrapSentMarker); ok {
			m.MarkBootstrapSent()
		}

		err = h.awaitBootstrapResponse(ctx, stream)
		if err == nil {
			if attempt > 1 {
				log.Info("[STREAM] bootstrap recovered on a new connection",
					"target", req.target, "attempts", attempt)
			}
			return &bootstrapSession{stream: stream, sk: sk, salt: salt}, nil
		}
		lastErr = err

		// 上层取消（核心停止、本地连接已断）：只关闭本流，不得失效连接——取消不是判死，
		// 这条连接可能健康且被同槽位的其他在飞流共享。
		if ctx.Err() != nil {
			_ = stream.Close()
			return nil, ctx.Err()
		}

		// 判死：失效本流所在的那条连接（CloseIdleConnections 关不掉承载活跃流的连接），
		// 只作用于本次请求自己的连接，不会误杀刚重试建立的新连接。
		invalidateDeadStream(stream)
		_ = stream.Close()

		if attempt < bootstrapMaxAttempts {
			log.Debug("[STREAM] bootstrap timed out, retrying on a new connection",
				"attempt", attempt, "target", req.target, "err", lastErr)
			settleDeadStream(stream)
			h.transport.CloseIdle()
			continue
		}
		return nil, lastErr
	}

	return nil, lastErr
}

// 窗口到点时用一次同连接探测区分"连接已死"与"服务端还没答复"。
func (h *StreamHandler) awaitBootstrapResponse(ctx context.Context, stream transport.Stream) error {
	ra, ok := stream.(transport.ResponseAwaiter)
	if !ok {
		return nil
	}

	waitCtx, cancel := context.WithTimeout(ctx, bootstrapResponseTimeout)
	err := ra.AwaitResponse(waitCtx)
	cancel()

	if err == nil {
		// 响应已就绪：成功，或服务端拒绝（非 200 已被传输层转成 HandshakeRejectedError）。
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	// 先问这条连接还能不能往返：服务端在解析目标域名之后才提交响应头，迟到不等于已死。
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

// 判死重试必须换连接，而 CloseIdleConnections 关不掉承载活跃流的连接。
func invalidateDeadStream(stream transport.Stream) {
	if inv, ok := stream.(transport.ConnInvalidator); ok {
		inv.InvalidateConn()
	}
}

// 等已关闭的流的 RoundTrip 收敛，随后的 CloseIdle 才能丢掉其余槽位的空闲连接。
func settleDeadStream(stream transport.Stream) {
	ra, ok := stream.(transport.ResponseAwaiter)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapSettleTimeout)
	defer cancel()
	_ = ra.AwaitResponse(ctx)
}

// 只分类第一次读取：流中途的失败意味着真正的流损坏，不是握手被拒。
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

func (h *StreamHandler) icmpStream(ctx context.Context, req streamRequest) ([]byte, error) {
	log.Debug("[STREAM] icmp open", "endpoint", req.endpoint, "target", req.target)

	s, err := h.newSession(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("icmp bootstrap: %w", err)
	}
	log.Debug("[STREAM] merged ICMP echo payload into bootstrap record", "bytes", req.firstPayloadBytes())
	defer s.stream.Close() //nolint:errcheck
	// 此路径只接收，但 tx 仍持有池化的记录缓冲区与 cover 注入器，必须关闭。声明在 stream 的
	// defer 之后，因此先执行（LIFO），避免向已关闭的流做冲刷。
	defer s.tx.Close() //nolint:errcheck

	frame, err := s.rx.ReadFrame()
	err = classifyFirstReadError(err)
	if err != nil {
		return nil, fmt.Errorf("read first reply frame: %w", err)
	}

	if frame.Type == protocol.FrameRST {
		return nil, fmt.Errorf("icmp rejected by server")
	}

	if frame.Type != protocol.FrameDATA {
		return nil, fmt.Errorf("expected DATA frame, got %d", frame.Type)
	}

	return frame.Payload, nil
}

type session struct {
	stream transport.Stream
	tx     shaper.Shaper
	rx     *crypto.DecryptedReader
}

func (h *StreamHandler) newSession(ctx context.Context, req streamRequest) (*session, error) {
	bs, err := h.openAndBootstrap(ctx, req)
	if err != nil {
		return nil, err
	}
	stream := bs.stream

	txWriter, err := bs.sk.NewWriter(stream, crypto.DirC2S, req.method)
	if err != nil {
		stream.Close() //nolint:errcheck
		return nil, fmt.Errorf("c2s session writer: %w", err)
	}

	shaperCfg := h.shaperCfg
	if req.batchWindowMS > 0 {
		shaperCfg.BatchWindowMS = req.batchWindowMS
	}
	tx := shaper.New(txWriter, shaperCfg)

	rx, err := bs.sk.NewReader(stream, crypto.DirS2C, req.method)
	if err != nil {
		_ = tx.Close()
		stream.Close() //nolint:errcheck
		return nil, fmt.Errorf("s2c session reader: %w", err)
	}

	return &session{stream: stream, tx: tx, rx: rx}, nil
}

func (h *StreamHandler) openStream(ctx context.Context, req streamRequest, localConn net.Conn) error {
	log.Debug("[STREAM] opening", "endpoint", req.endpoint, "target", req.target)

	if localConn != nil {
		_ = localConn.SetReadDeadline(time.Now().Add(8 * time.Millisecond))
		// 这一读只取连接建立时已到达的首批数据，因此用最小档位起步。NewFrameDATA 会复制载荷，
		// 缓冲可以拼帧后立即归还。
		buf := bytespool.Get(protocol.MinRecordBufferSize)
		n, rErr := localConn.Read(buf)
		_ = localConn.SetReadDeadline(time.Time{})
		if n > 0 {
			req = req.withFrames(protocol.NewFrameDATA(buf[:n]))
			log.Debug("[STREAM] merged first DATA into bootstrap record", "bytes", n, "read_err", rErr)
		}
		bytespool.MustPut(buf)
	}

	s, err := h.newSession(ctx, req)
	if err != nil {
		return fmt.Errorf("tcp bootstrap: %w", err)
	}
	defer s.tx.Close() //nolint:errcheck
	log.Debug("[STREAM] handshake sent", "target", req.target)

	err = h.relay(req.target, localConn, s.tx, s.rx, s.stream)
	log.Debug("[STREAM] relay finished", "endpoint", req.endpoint, "target", req.target, "err", err)
	return err
}

func (h *StreamHandler) relay(target string, localConn net.Conn, tx shaper.Shaper, rx *crypto.DecryptedReader, stream transport.Stream) error {
	m := stats.NewStreamMeter("client", target)
	defer m.Close()

	closeAll := relay.CloseBoth(stream, localConn)

	// 提前关闭即将被驱逐的 slot 上的空闲流：它们就是残留的 keep-alive 或半关闭连接，关掉能
	// 让 slot 的轮换不必等完整的空闲超时。
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

// 读缓冲按需增长；TCP 上缩短缓冲只会多几次 Read，不会丢数据。
func (h *StreamHandler) copyLocalToRemote(src net.Conn, tx shaper.Shaper, signalActivity func()) error {
	r := netbuf.NewReader(protocol.MinRecordBufferSize, config.TCPStreamBufferSize)
	defer r.Release()
	for {
		buf := r.Buf()
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
			// 交出数据之后才换档：Grow 会把 buf 归还池。
			if n == len(buf) {
				r.Grow()
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

// 下行预读必须与本地写解耦：h2 连接级窗口只在应用读 body 时归还，本地写一阻塞就会把本流的
// 接收窗口钉死，进而拖住同一连接上的其他流。队列满即恢复背压，深度决定单流最多预读多少帧
// （约 1–2MB 明文）。
const remotePrefetchFrames = 64

func (h *StreamHandler) copyRemoteToLocal(rx *crypto.DecryptedReader, dst net.Conn, signalActivity func(), m *stats.StreamMeter) error {
	// err 非空表示读端已终止；终态与数据走同一条队列，不再需要第二组完成信号。
	type prefetchedFrame struct {
		data []byte
		fin  bool
		rst  bool
		err  error
	}

	frames := make(chan prefetchedFrame, remotePrefetchFrames)
	done := make(chan struct{})
	defer close(done)

	go func() {
		defer close(frames)
		first := true
		for {
			// 消费者已返回时不再解密下一帧：send 上的 select 在两边都就绪时会随机选中队列。
			select {
			case <-done:
				return
			default:
			}

			frame, err := rx.ReadFrame()
			if first {
				first = false
				err = classifyFirstReadError(err)
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					log.Debug("[STREAM] remote read error", "err", err)
					select {
					case frames <- prefetchedFrame{err: err}:
					case <-done:
					}
				}
				return
			}

			switch frame.Type {
			case protocol.FrameDATA:
				signalActivity()
				if len(frame.Payload) == 0 {
					continue
				}
				select {
				case frames <- prefetchedFrame{data: frame.Payload}:
				case <-done:
					return
				}
			case protocol.FrameFIN:
				signalActivity()
				select {
				case frames <- prefetchedFrame{fin: true}:
				case <-done:
				}
				return
			case protocol.FrameRST:
				select {
				case frames <- prefetchedFrame{rst: true}:
				case <-done:
				}
				return
			case protocol.FramePADDING, protocol.FrameCOVER:
			}
		}
	}()

	for item := range frames {
		if item.err != nil {
			return item.err
		}
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
	return nil
}

// 瞬时或预期的流失败（空闲超时、对端重置、握手被拒、连接断开等）记 Debug：
// 连接判死时它们会同时命中许多流。
func isTransientStreamError(err error) bool {
	if errors.Is(err, ErrStreamIdleTimeout) || errors.Is(err, ErrStreamReset) {
		return true
	}
	if errors.Is(err, ErrServerRejectedHandshake) || transport.IsHandshakeRejected(err) {
		return true
	}
	if errors.Is(err, transport.ErrConnRetired) {
		return true
	}
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "client connection lost") ||
		strings.Contains(msg, "force closed via clientconn.close") ||
		strings.Contains(msg, "http2: stream closed") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection was aborted")
}

// 刻意不归类"connection reset by peer"：那是流级别失败，由 isTransientStreamError 负责。
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

// 手工拼装不经过整形器的预冲刷边界，可用载荷必须自己算：明文上限减去 target 与帧头
// 9 字节（3+3+3）。
func bootstrapMaxPayload(target string) int {
	return protocol.MaxWriteRecordPlaintext - len(target) - 9
}

func (h *StreamHandler) OpenUDPExchange(ctx context.Context, target string, method protocol.Method, firstPayload []byte) (*UDPExchange, error) {
	stats.RecordUDPAssociation()
	log.Debug("[UDP_EXCHANGE] opening", "target", target)

	// 只有合并后的明文保证能被加密层接受时才合并首个数据报（见 bootstrapMaxPayload）。过大
	// 的首个数据报改为在握手之后立即发送，而不是让整个交换失败。
	req := udpStreamRequest(target, method)
	mergeFirst := false
	if len(firstPayload) > 0 {
		if len(firstPayload) <= bootstrapMaxPayload(target) {
			mergeFirst = true
			req = req.withFrames(protocol.NewFrameDATAGRAM(firstPayload))
			// 合并进引导记录的数据报不走 Send，上行记账只能在这里补，放在创建点而不是各调用方。
			stats.RecordRawBytesSent(len(firstPayload))
			log.Debug("[UDP_EXCHANGE] merged first DATAGRAM into bootstrap record", "bytes", len(firstPayload))
		} else {
			log.Debug("[UDP_EXCHANGE] first DATAGRAM too large for bootstrap, sending after handshake", "bytes", len(firstPayload))
		}
	}

	// UDP 用较短的 1ms 批处理窗口而非每个数据报强制冲刷：突发合并进单条记录，空闲触发的
	// 定时器把稀疏流量的延迟限制在约 1ms。
	s, err := h.newSession(ctx, req.withBatchWindow(1))
	if err != nil {
		return nil, fmt.Errorf("udp bootstrap: %w", err)
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

// 上行记账在这里、下行在 Receive：UDP 交换不经过 relay.Bidirectional，
// 这两个方法是 UDP 流量进入「原始字节」计数器的唯一位置。
func (ue *UDPExchange) Send(data []byte) error {
	ue.mu.Lock()
	defer ue.mu.Unlock()
	ue.lastSeen.Store(time.Now().UnixNano())
	// 用 NewFrameWithPayload 而非 NewFrameDATAGRAM：后者会复制一份载荷，而整形器在 PushFrame
	// 内就会拷贝。载荷所有权不变（putPayload 为 false）。
	frame := protocol.NewFrameWithPayload(protocol.FrameDATAGRAM, data)
	stats.RecordRawBytesSent(len(data))
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
			// 下行记账与 Send 配对：只有真正交给客户端的 DATAGRAM 才算流量。
			stats.RecordRawBytesRecv(len(frame.Payload))
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

// FIN 必须在 tx.Close 之前推入：shaper 一旦开始关闭，PushFrame 就会丢弃帧。
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
