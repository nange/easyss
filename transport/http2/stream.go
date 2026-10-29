package http2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

type roundTripResult struct {
	resp *http.Response
	err  error
}

type http2Stream struct {
	w      *io.PipeWriter
	cancel context.CancelFunc
	done   func()
	slot   *transportSlot

	// respReady 在 RoundTrip 结果落定后关闭：Read 与 AwaitResponse 都等它，但只有 Read 消费响应体。
	respReady chan struct{}
	readyOnce sync.Once

	// endpoint/target 只为日志归因，不参与任何调度或协议决策。
	endpoint string
	target   string

	// bootstrapSentAt 是 bootstrap 记录冲刷完成的时刻（UnixNano，0 表示未打戳）。服务端在
	// 拨号源端之前就应答，因此到响应到达的差值就是纯路径 RTT，不含源端耗时。
	bootstrapSentAt atomic.Int64

	// gen 是本流提交请求时所用的那一代连接，由发起 RoundTrip 的 goroutine 在提交前写入。
	gen atomic.Pointer[slotTransport]

	// trace 由本流独占。h2 在写出请求之前触发 GotConn，因此这条流实际落在哪条连接上不靠
	// 猜：同一代里 net/http 可能重拨并换掉身份，失效必须按它。
	trace httptrace.ClientTrace
	// conn 是 trace 记录的身份；nil 表示这条流从未拿到连接（拨号阶段就失败了）。
	conn atomic.Pointer[slotConn]

	// liveness 为 nil 时 ConnAlive 报无法判定。
	liveness func(ctx context.Context, gen *slotTransport) (alive, ok bool)

	// slowRTT 为 nil（测试里裸构造的流）时越界样本照常逐条打印。
	slowRTT *slowRTTLogLimiter

	mu      sync.Mutex
	r       io.ReadCloser
	respErr error
	closed  bool

	rtErrMu sync.Mutex
	rtErr   error // RoundTrip 错误，捕获以便在 Write() 中提供更好的诊断

	// heavy 流跟踪：流够格成为 heavy 后标记自己的槽位，使新流避开那条连接。
	startTime   time.Time
	transferred atomic.Int64
	heavyMu     sync.Mutex
	heavyState  atomic.Int32
}

// heavy 流状态机：首次够格时 idle→marked，关闭时 marked→released。互斥锁把每次转换与槽位
// 计数更新配对，因此 Read/Write/Close 怎么交错都不会泄漏计数。
const (
	heavyIdle     int32 = iota // 流从未够格成为 heavy
	heavyMarked                // 已够格：slot.heavy 已递增
	heavyReleased              // 已关闭：若曾标记则 slot.heavy 已递减
)

// 累计下载字节数：计入槽位（健康与轮换信号）和 heavy 检测器。
func (s *http2Stream) trackRead(n int) {
	if s.slot == nil || n <= 0 {
		return
	}
	s.slot.bytesRecv.Add(int64(n))
	s.slot.connBytes.Add(int64(n))
	s.accumulate(n)
}

// 中间设备按任一方向的总字节数限速，上传密集的连接也必须触发轮换。
func (s *http2Stream) trackWrite(n int) {
	if s.slot == nil || n <= 0 {
		return
	}
	s.slot.connBytes.Add(int64(n))
	s.accumulate(n)
}

// 首次够格时标记槽位：跨越快速大小阈值，或存活足够久且承载了慢速阈值。
func (s *http2Stream) accumulate(n int) {
	if s.slot == nil || n <= 0 {
		return
	}
	total := s.transferred.Add(int64(n))
	if s.heavyState.Load() != heavyIdle {
		return
	}
	fast := total >= config.HeavyStreamThresholdBytes
	slow := total >= config.HeavyStreamSlowThresholdBytes &&
		time.Since(s.startTime) >= config.HeavyStreamMinAge
	if !fast && !slow {
		return
	}
	s.heavyMu.Lock()
	defer s.heavyMu.Unlock()
	if s.heavyState.CompareAndSwap(heavyIdle, heavyMarked) {
		s.slot.heavy.Add(1)
	}
}

// 每条流恰好释放一次槽位的 heavy 标记；它与 accumulate 可能并发。
func (s *http2Stream) releaseHeavy() {
	if s.slot == nil {
		return
	}
	s.heavyMu.Lock()
	defer s.heavyMu.Unlock()
	switch s.heavyState.Load() {
	case heavyMarked:
		s.heavyState.Store(heavyReleased)
		s.slot.heavy.Add(-1)
	case heavyIdle:
		s.heavyState.Store(heavyReleased)
	}
}

func (s *http2Stream) setRoundTripErr(err error) {
	s.rtErrMu.Lock()
	s.rtErr = err
	s.rtErrMu.Unlock()
}

func (s *http2Stream) MarkBootstrapSent() {
	s.bootstrapSentAt.Store(time.Now().UnixNano())
}

func (s *http2Stream) Read(p []byte) (int, error) {
	// Close 会取消请求，使 RoundTrip 返回并落定结果。
	if s.respReady != nil {
		<-s.respReady
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	r := s.r
	respErr := s.respErr
	s.mu.Unlock()

	if r == nil {
		s.done()
		if respErr != nil {
			return 0, s.wrapRetired(respErr)
		}
		return 0, io.EOF
	}

	n, err := r.Read(p)
	if n > 0 {
		s.trackRead(n)
	}
	if err != nil {
		s.done()
		err = s.wrapRetired(err)
	}
	return n, err
}

func (s *http2Stream) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if n > 0 {
		s.trackWrite(n)
	}
	if err != nil {
		s.done()
		if errors.Is(err, io.ErrClosedPipe) {
			s.rtErrMu.Lock()
			rtErr := s.rtErr
			s.rtErrMu.Unlock()
			if rtErr != nil {
				// 同时包裹两个错误，调用方仍能匹配 io.ErrClosedPipe 做重试决策。
				return n, s.wrapRetired(fmt.Errorf("%w: %w", io.ErrClosedPipe, rtErr))
			}
		}
		return n, s.wrapRetired(err)
	}
	return n, err
}

// 给连接代已作废的读写错误加上 transport.ErrConnRetired：判死与 net/http 自然回收都会换代，
// 代不一致即说明这条流不可能再健康。io.EOF 是正常结束，不能包装。
func (s *http2Stream) wrapRetired(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, transport.ErrConnRetired) {
		return err
	}
	gen := s.gen.Load()
	if gen == nil || s.slot == nil || s.slot.generation() == gen {
		return err
	}
	return fmt.Errorf("%w: %w", transport.ErrConnRetired, err)
}

// 流若已在上层被放弃，响应体不会有人读取，必须在这里关闭，避免遗留一条无人读取的流。
func (s *http2Stream) deliver(res roundTripResult) {
	var body io.ReadCloser
	if res.resp != nil {
		body = res.resp.Body
	}
	s.mu.Lock()
	s.r = body
	s.respErr = res.err
	if s.closed && s.r != nil {
		_ = s.r.Close()
		s.r = nil
		if s.respErr == nil {
			s.respErr = io.ErrClosedPipe
		}
	}
	s.mu.Unlock()

	s.setRoundTripErr(res.err)
	if res.err == nil && res.resp != nil {
		// 在结果落定的时刻采样，避免把代理层的等待与调度算进路径 RTT。
		if t0 := s.bootstrapSentAt.Load(); t0 > 0 {
			d := time.Since(time.Unix(0, t0))
			stats.RecordRTT(d)
			// 越界样本额外记 Warn 并限流：平均值只能看出变慢，日志回答是谁慢。
			s.slowRTT.log(d, slowRTTSample{
				source:   slowRTTSourceStream,
				endpoint: s.endpoint,
				target:   s.target,
				slot:     s.slot,
			})
		}
	}
	s.readyOnce.Do(func() { close(s.respReady) })
}

func (s *http2Stream) roundTripErr() error {
	s.rtErrMu.Lock()
	defer s.rtErrMu.Unlock()
	return s.wrapRetired(s.rtErr)
}

// 服务端以非 200 拒绝握手同样是结果已就绪，重试决策不应把它当作网络故障。
func (s *http2Stream) AwaitResponse(ctx context.Context) error {
	if s.respReady == nil {
		return nil
	}
	select {
	case <-s.respReady:
		if err := s.roundTripErr(); err != nil && !transport.IsHandshakeRejected(err) {
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ok=false 表示无法判定（未配置探测令牌或尚未提交）。必须探测本流自己那一代：否则仍绑在
// 旧连接上的流会被新连接的健康状况顶替成"活着"，继续等一条已经死掉的连接。
func (s *http2Stream) ConnAlive(ctx context.Context) (alive, ok bool) {
	if s.liveness == nil {
		return false, false
	}
	gen := s.gen.Load()
	if gen == nil {
		return false, false
	}
	return s.liveness(ctx, gen)
}

// GotConn 在请求写出前触发；只认第一条，传输层万一重试也不会覆盖成后来的连接。
func (s *http2Stream) noteConn(info httptrace.GotConnInfo) {
	if tc, ok := info.Conn.(*trackedConn); ok && tc.self != nil {
		s.conn.CompareAndSwap(nil, tc.self)
	}
}

// 身份来自 GotConn：只失效本流实际用过的那条连接，同代重拨出的新连接不会被连带关掉。
// 没有身份说明这条流从未拿到连接，没有可关的对象。
func (s *http2Stream) InvalidateConn() {
	gen := s.gen.Load()
	conn := s.conn.Load()
	if s.slot == nil || gen == nil || conn == nil {
		return
	}
	s.slot.invalidateConnIf(gen, conn, "stream dead")
}

func (s *http2Stream) CloseWrite() error {
	return s.w.Close()
}

func (s *http2Stream) Close() error {
	defer s.done()
	s.cancel()
	_ = s.w.Close()

	s.mu.Lock()
	s.closed = true
	// 结果已交付但无人读取（判死重试、上层取消）时关闭它，避免遗留 HTTP/2 流；
	// 结果迟到的情形由 deliver 处理。
	r := s.r
	s.r = nil
	if s.respErr == nil {
		s.respErr = io.ErrClosedPipe
	}
	s.mu.Unlock()

	if r != nil {
		return r.Close()
	}
	return nil
}

var (
	_ transport.Stream          = (*http2Stream)(nil)
	_ transport.ResponseAwaiter = (*http2Stream)(nil)
	_ transport.ConnLiveness    = (*http2Stream)(nil)
	_ transport.ConnInvalidator = (*http2Stream)(nil)
)

// 代理层据此用 relay.BidirectionalWithDrain 提前关闭空闲流，使 keep-alive 与半关闭连接
// 无法推迟轮换。
func (s *http2Stream) SlotDraining() bool {
	return s.slot != nil && (s.slot.expiring.Load() || s.slot.degraded.Load())
}
