package relay

import (
	"errors"
	"fmt"
	"io"
	"time"
)

// CloseBoth 给 Bidirectional 的 onClose 用：中继每次终止恰好调用一次，这里关掉所有非 nil 的 closer。
func CloseBoth(closers ...io.Closer) func() {
	return func() {
		for _, c := range closers {
			if c != nil {
				_ = c.Close()
			}
		}
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

type Result struct {
	Err      error
	TimedOut bool
	// Drained 表示中继被 drain 机制提前终止：所属 slot 该淘汰且已空闲 drainIdle，不等满空闲超时。
	Drained bool
}

// 两个拷贝 goroutine 共享一个空闲超时；调用方须在有数据流动时调用 signalActivity。
// 终止时 onClose 恰好被调用一次，Result.Err 取第一个非 nil 非 EOF 的错误。
func Bidirectional(idleTimeout time.Duration, onClose func(), srcToDst, dstToSrc func(signalActivity func()) error) Result {
	return bidirectional(idleTimeout, nil, 0, onClose, srcToDst, dstToSrc)
}

// 在 Bidirectional 之上加提前收尾：drainWhen 报告 slot 该淘汰且流已空闲 drainIdle 即关闭，
// 有流量流过的流永不被 drain。drainWhen 为 nil 或 drainIdle <= 0 时等同 Bidirectional。
func BidirectionalWithDrain(idleTimeout time.Duration, drainWhen func() bool, drainIdle time.Duration, onClose func(), srcToDst, dstToSrc func(signalActivity func()) error) Result {
	return bidirectional(idleTimeout, drainWhen, drainIdle, onClose, srcToDst, dstToSrc)
}

func bidirectional(idleTimeout time.Duration, drainWhen func() bool, drainIdle time.Duration, onClose func(), srcToDst, dstToSrc func(signalActivity func()) error) Result {
	activity := make(chan struct{}, 1)
	signalActivity := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}

	errCh := make(chan error, 2)
	go func() { errCh <- srcToDst(signalActivity) }()
	go func() { errCh <- dstToSrc(signalActivity) }()

	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()

	// idleSince 与定时器同步重启，drain 检查与它比较，宽限期的基准才与空闲超时一致。
	idleSince := time.Now()
	resetIdle := func() {
		idleSince = time.Now()
		resetTimer(timer, idleTimeout)
	}

	// 必须周期性采样而不是按状态变化重新武装：drainWhen 由健康检查循环异步翻转。tick 取
	// drainIdle 的分数，进入空闲后 drain 在 drainIdle..drainIdle+tick 内触发。
	var drainC <-chan time.Time
	if drainWhen != nil && drainIdle > 0 {
		tick := max(drainIdle/6, 10*time.Millisecond)
		drainTicker := time.NewTicker(tick)
		defer drainTicker.Stop()
		drainC = drainTicker.C
	}

	done := 0
	var firstErr error
	for done < 2 {
		select {
		case err := <-errCh:
			done++
			if err != nil && !errors.Is(err, io.EOF) && firstErr == nil {
				firstErr = err
			}
			if firstErr != nil || done == 2 {
				if onClose != nil {
					onClose()
				}
				return Result{Err: firstErr}
			}
			resetIdle()
		case <-activity:
			resetIdle()
		case <-drainC:
			if drainWhen() && time.Since(idleSince) >= drainIdle {
				if onClose != nil {
					onClose()
				}
				// 非阻塞排空，让两个 goroutine 能干净退出。
				for range 2 {
					select {
					case <-errCh:
					default:
					}
				}
				return Result{
					Err:      fmt.Errorf("stream drained: idle for %v while the slot is due for eviction", drainIdle),
					TimedOut: true,
					Drained:  true,
				}
			}
		case <-timer.C:
			if onClose != nil {
				onClose()
			}
			// 非阻塞排空，让两个 goroutine 能干净退出。
			for range 2 {
				select {
				case <-errCh:
				default:
				}
			}
			return Result{
				Err:      fmt.Errorf("relay idle timeout after %v", idleTimeout),
				TimedOut: true,
			}
		}
	}
	// 实际不可达：所有把 done 增到 2 的路径都已直接返回。
	return Result{Err: firstErr}
}
