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
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

type roundTripResult struct {
	resp *http.Response
	err  error
}

type http2Stream struct {
	w      *io.PipeWriter
	respCh <-chan roundTripResult
	cancel context.CancelFunc
	done   func()
	slot   *transportSlot

	// bootstrapSentAt 是客户端完成冲刷加密 bootstrap 记录（请求体）的时刻。
	// 服务端在拨号源端之前就用响应头应答，因此该时间戳与响应到达之间的
	// 时间差就是纯粹的 client<->server 路径 RTT（不含源端耗时）。
	// 以 UnixNano 存储；0 表示从未打戳。
	bootstrapSentAt atomic.Int64

	mu       sync.Mutex
	r        io.ReadCloser
	respErr  error
	respOnce sync.Once
	closed   bool

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
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	needResp := s.r == nil && s.respErr == nil
	s.mu.Unlock()

	if needResp {
		s.respOnce.Do(func() {
			res := <-s.respCh
			s.mu.Lock()
			if res.err != nil {
				s.respErr = res.err
			} else {
				s.r = res.resp.Body
				// 响应头已到达：若 MarkBootstrapSent 已打戳（bootstrap 记录
				// 已冲刷），这就是纯路径 RTT——服务端在拨号源端之前就提交
				// 了响应。
				if t0 := s.bootstrapSentAt.Load(); t0 > 0 {
					stats.RecordRTT(time.Since(time.Unix(0, t0)))
				}
			}
			// 如果在等待响应时 Close() 已被调用，响应体刚刚到达但永远不会
			// 有人读取或关闭它。现在就关闭它以释放 HTTP/2 流及其缓冲区，
			// 并向调用方呈现关闭错误。
			if s.closed && s.r != nil {
				_ = s.r.Close()
				s.r = nil
				if s.respErr == nil {
					s.respErr = io.ErrClosedPipe
				}
			}
			s.mu.Unlock()
		})
	}

	s.mu.Lock()
	r := s.r
	respErr := s.respErr
	closed := s.closed
	s.mu.Unlock()

	if closed {
		return 0, io.ErrClosedPipe
	}
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

func (s *http2Stream) CloseWrite() error {
	return s.w.Close()
}

func (s *http2Stream) Close() error {
	defer s.done()
	s.cancel()
	_ = s.w.Close()

	s.mu.Lock()
	r := s.r
	s.closed = true
	s.mu.Unlock()

	if r != nil {
		return r.Close()
	}
	return nil
}

var _ transport.Stream = (*http2Stream)(nil)

// SlotDraining 报告流的槽位是否已到驱逐期：连接超过生命周期或字节限制
// （expiring），或已被证实持续缓慢（degraded），因此应被回收。代理层断言
// 流实现了 transport.SlotDrainingStream，并通过 relay.BidirectionalWithDrain
// 提前关闭空闲流，使徘徊的 keep-alive 和半关闭连接无法把槽位的轮换/退役
// 推迟到完整的中继空闲超时。活跃流永远不会被排空：中继只会在它们空闲
// ExpiringStreamDrainIdle 时间后才关闭它们。
func (s *http2Stream) SlotDraining() bool {
	return s.slot != nil && (s.slot.expiring.Load() || s.slot.degraded.Load())
}
