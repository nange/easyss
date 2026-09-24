package http2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
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

	// respReady 在 RoundTrip 结果（r/respErr）落定后关闭：Read 与
	// AwaitResponse 都等待它，但只有 Read 消费响应体。
	respReady chan struct{}
	readyOnce sync.Once

	// bootstrapSentAt 是客户端完成冲刷加密 bootstrap 记录（请求体）的时刻。
	// 服务端在拨号源端之前就用响应头应答，因此该时间戳与响应到达之间的
	// 时间差就是纯粹的 client<->server 路径 RTT（不含源端耗时）。
	// 以 UnixNano 存储；0 表示从未打戳。
	bootstrapSentAt atomic.Int64

	// connInUse 是本流实际使用过的底层连接身份，在第一次 body 写完成时快照
	// （见 snapshotConnInUse）。InvalidateConn 只关闭它，并按槽位指针的身份
	// CAS 决定唯一赢家。
	connInUse atomic.Pointer[slotConn]

	// liveness 在本流所在连接上做一次轻量存活探测（见 transport.ConnLiveness）；
	// 为 nil 时 ConnAlive 报告"无法判定"（未配置探测令牌）。
	liveness func(ctx context.Context, slot *transportSlot) (alive, ok bool)

	mu      sync.Mutex
	r       io.ReadCloser
	respErr error
	closed  bool

	rtErrMu sync.Mutex
	rtErr   error // RoundTrip 错误，捕获以便在 Write() 中提供更好的诊断

	// heavy 流跟踪：一旦流够格成为 heavy（快速的大传输，或差链路上的慢
	// 传输），它就会标记自己的槽位，使新流避免共享那条连接。见下文
	// heavyIdle/heavyMarked/heavyReleased。
	startTime   time.Time
	transferred atomic.Int64
	heavyMu     sync.Mutex
	heavyState  atomic.Int32
}

// heavy 流状态机：流在首次够格成为 heavy 时从 heavyIdle 转换到 heavyMarked，
// 关闭时从 heavyMarked 转换到 heavyReleased。互斥锁把每次转换与其槽位计数
// 更新配对，因此无论 Read/Write/Close 如何交错，slot.heavy 都不会泄漏。
const (
	heavyIdle     int32 = iota // 流从未够格成为 heavy
	heavyMarked                // 已够格：slot.heavy 已递增
	heavyReleased              // 已关闭：若曾标记则 slot.heavy 已递减
)

// trackRead 累计下载字节数：计入槽位（传输健康与连接轮换信号）和 heavy 流
// 检测器。
func (s *http2Stream) trackRead(n int) {
	if s.slot == nil || n <= 0 {
		return
	}
	s.slot.bytesRecv.Add(int64(n))
	s.slot.connBytes.Add(int64(n))
	s.accumulate(n)
}

// trackWrite 累计上传字节数：计入连接轮换计数器（上传密集的连接也必须触发
// 轮换，因为中间设备按任一方向的总字节数限速）和 heavy 流检测器。
func (s *http2Stream) trackWrite(n int) {
	if s.slot == nil || n <= 0 {
		return
	}
	s.slot.connBytes.Add(int64(n))
	s.accumulate(n)
}

// accumulate 把数据喂给 heavy 流检测器，并在流首次够格时把所属槽位标记为
// heavy：要么跨越了快速大小阈值，要么存活足够久且至少承载了慢速阈值
// （慢链路上即使小传输也会持续很久）。
func (s *http2Stream) accumulate(n int) {
	if s.slot == nil || n <= 0 {
		return
	}
	total := s.transferred.Add(int64(n))
	// 快路径：标记每条流至多发生一次；一旦状态离开 heavyIdle（已标记或
	// 已释放）就无事可做。
	if s.heavyState.Load() != heavyIdle {
		return
	}
	fast := total >= sharedconfig.HeavyStreamThresholdBytes
	slow := total >= sharedconfig.HeavyStreamSlowThresholdBytes &&
		time.Since(s.startTime) >= sharedconfig.HeavyStreamMinAge
	if !fast && !slow {
		return
	}
	s.heavyMu.Lock()
	defer s.heavyMu.Unlock()
	if s.heavyState.CompareAndSwap(heavyIdle, heavyMarked) {
		s.slot.heavy.Add(1)
	}
}

// releaseHeavy 每条流恰好释放一次槽位的 heavy 标记。它从流的 done 回调
// （由 sync.OnceFunc 守护）中调用，而 accumulate 可能从 Read/Write 并发
// 运行。互斥锁把每次状态转换与计数更新配对，因此 slot.heavy 不会泄漏。
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

// setRoundTripErr 存储 RoundTrip 错误，供管道写入以 io.ErrClosedPipe 失败时
// 的 Write() 使用。
func (s *http2Stream) setRoundTripErr(err error) {
	s.rtErrMu.Lock()
	s.rtErr = err
	s.rtErrMu.Unlock()
}

// MarkBootstrapSent 记录 bootstrap 记录冲刷到传输层的时刻。响应头大约在一个
// 路径 RTT 后到达（服务端在拨号源端之前应答），Read() 把它记录为纯粹的
// client<->server RTT 样本。
func (s *http2Stream) MarkBootstrapSent() {
	s.bootstrapSentAt.Store(time.Now().UnixNano())
}

func (s *http2Stream) Read(p []byte) (int, error) {
	// 结果落定前阻塞等待；Close 会取消请求，使 RoundTrip 返回并落定结果。
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
			return 0, respErr
		}
		return 0, io.EOF
	}

	n, err := r.Read(p)
	if n > 0 {
		s.trackRead(n)
	}
	if err != nil {
		s.done()
	}
	return n, err
}

func (s *http2Stream) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if n > 0 {
		s.trackWrite(n)
		s.snapshotConnInUse()
	}
	if err != nil {
		s.done()
		if errors.Is(err, io.ErrClosedPipe) {
			s.rtErrMu.Lock()
			rtErr := s.rtErr
			s.rtErrMu.Unlock()
			if rtErr != nil {
				// 同时包裹两个错误，使调用方仍能匹配 io.ErrClosedPipe 做重试
				// 决策，同时也能看到根本原因。
				return n, fmt.Errorf("%w: %w", io.ErrClosedPipe, rtErr)
			}
		}
	}
	return n, err
}

// snapshotConnInUse 记住承载本流的底层连接。第一次 body 写完成时连接必然已经
// 建立：net/http 必须先写出请求头、拿到连接，才会去读取请求体；而每个槽位的
// http.Transport 设了 MaxConnsPerHost=1，同一时刻至多一条连接，因此这个快照
// 就是"我自己实际用过的那条"。InvalidateConn 据此只关闭它。
func (s *http2Stream) snapshotConnInUse() {
	if s.slot == nil || s.connInUse.Load() != nil {
		return
	}
	if sc := s.slot.conn.Load(); sc != nil {
		s.connInUse.CompareAndSwap(nil, sc)
	}
}

// deliver 落定 RoundTrip 的结果：先存入 r/respErr（Write 的诊断与
// AwaitResponse 都要读它），再关闭 respReady 唤醒等待方。若流在结果到达前
// 已被上层放弃（判死重试或取消），响应体不会再有人读取，因此在这里关闭它，
// 避免遗留一条无人读取的 HTTP/2 流。
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
		// 响应头已到达：若 MarkBootstrapSent 已打戳（bootstrap 记录已冲刷），
		// 这就是纯路径 RTT——服务端在拨号源端之前就提交了响应。在结果落定的
		// 时刻采样，避免把代理层等待/调度的时间算进路径 RTT。
		if t0 := s.bootstrapSentAt.Load(); t0 > 0 {
			stats.RecordRTT(time.Since(time.Unix(0, t0)))
		}
	}
	s.readyOnce.Do(func() { close(s.respReady) })
}

// roundTripErr 返回落定后的 RoundTrip 错误：Read 与 AwaitResponse 对它的解读
// 一致，但拒绝类错误在 AwaitResponse 中被视为"结果已就绪"。
func (s *http2Stream) roundTripErr() error {
	s.rtErrMu.Lock()
	defer s.rtErrMu.Unlock()
	return s.rtErr
}

// AwaitResponse 等待 RoundTrip 结果就绪而不消费响应体
// （见 transport.ResponseAwaiter）：服务端以非 200 拒绝握手同样是"结果已就绪"，
// 重试决策不应把它当作网络故障（分类留给首次 Read）。ctx 结束时返回 ctx.Err()。
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

// ConnAlive 在本流所在槽位的连接上做一次轻量存活探测
// （见 transport.ConnLiveness）。ok=false 表示无法判定（未配置探测令牌），
// 调用方应按判死处理。
func (s *http2Stream) ConnAlive(ctx context.Context) (alive, ok bool) {
	if s.slot == nil || s.liveness == nil {
		return false, false
	}
	return s.liveness(ctx, s.slot)
}

// InvalidateConn 强制关闭本流实际使用过的底层连接
// （见 transport.ConnInvalidator），使下一次 Open 重新拨号。身份 CAS 同时挡住
// 两件事：同一连接被多条流重复失效（只有赢家执行），以及误杀后来新建的连接
// （新连接身份不同，CAS 必然失败）。
func (s *http2Stream) InvalidateConn() {
	sc := s.connInUse.Load()
	if sc == nil || s.slot == nil {
		return
	}
	if s.slot.conn.CompareAndSwap(sc, nil) {
		s.slot.resetRotation()
		_ = sc.c.Close()
		// 这是连接级事件，与 slot grown/rotated/retired 同级放在 Info：身份 CAS
		// 保证每条被丢弃的连接恰好记一条，同一连接上的多条流同时判死也不会刷屏。
		// 默认 Info 级别下它是"判死即换连接"唯一可见的锚点（逐流的判死原因与
		// 重试决策在代理层记 Debug，见 client/proxy/stream.go）。
		log.Info("[TRANSPORT] connection invalidated",
			"slot", s.slot.idx,
			"active_streams", s.slot.active.Load())
	}
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
	// 结果可能已经交付但还没有人读取（判死重试、上层取消）：关闭它，避免
	// 遗留一条无人读取的 HTTP/2 流。结果迟到的情形由 deliver 处理。
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

// SlotDraining 报告流的槽位是否已到驱逐期：连接超过生命周期或字节限制
// （expiring），或已被证实持续缓慢（degraded），因此应被回收。代理层断言
// 流实现了 transport.SlotDrainingStream，并通过 relay.BidirectionalWithDrain
// 提前关闭空闲流，使徘徊的 keep-alive 和半关闭连接无法把槽位的轮换/退役
// 推迟到完整的中继空闲超时。活跃流永远不会被排空：中继只会在它们空闲
// ExpiringStreamDrainIdle 时间后才关闭它们。
func (s *http2Stream) SlotDraining() bool {
	return s.slot != nil && (s.slot.expiring.Load() || s.slot.degraded.Load())
}
