package relay

import (
	"errors"
	"fmt"
	"io"
	"time"
)

// CloseBoth 返回 Bidirectional 的调用方所需的 onClose 回调：每次调用会关闭
// 所有非 nil 的 closer。中继在每次终止时恰好调用一次 onClose，且三处调用点
// （客户端代理路径、客户端直连路径、服务端 TCP handler）关闭的都是同一对连接，
// 因此该闭包在这里只定义一次，而不是重复书写。
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
	// Drained 表示中继被 drain 机制提前终止（BidirectionalWithDrain）：
	// 当 drainWhen 报告所属 slot 该被淘汰时，流空闲超过 drainIdle 即被关闭，
	// 而无需等待完整的空闲超时。
	Drained bool
}

// Bidirectional 并发运行两个拷贝 goroutine，共享同一个空闲超时。传给每个拷贝
// 函数的 signalActivity 回调应在有数据流动时调用，以重置空闲计时器。如果
// idleTimeout 内没有观察到任何活动，则调用 onClose 并返回超时错误。
//
// 中继终止（无论是完成、出错还是超时）时，onClose 回调恰好被调用一次。
//
// 每个拷贝函数在干净 EOF 时返回 nil，否则返回错误。返回第一个非 nil、
// 非 EOF 的错误。若两个拷贝都无错误地完成，则返回 nil。
func Bidirectional(idleTimeout time.Duration, onClose func(), srcToDst, dstToSrc func(signalActivity func()) error) Result {
	return bidirectional(idleTimeout, nil, 0, onClose, srcToDst, dstToSrc)
}

// BidirectionalWithDrain 是 Bidirectional 加上提前关闭的 drain 机制：
// 当 drainWhen 报告中继该收尾时（例如所属连接 slot 到期需要轮换或退役），
// 已空闲至少 drainIdle 的中继会被关闭，而不用等满整个空闲超时。活动
// （signalActivity 或某个拷贝完成）会重新启动空闲计时，因此持续有流量的
// 流永远不会被 drain——只有迟迟空闲的连接才会，而正是它们在推迟 slot 轮换。
// drainWhen 为 nil 或 drainIdle <= 0 时该机制被禁用，行为与 Bidirectional
// 完全相同。
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

	// idleSince 记录中继空闲计时器启动的时刻，与定时器保持同步：
	// 两者都会在收到活动或某个拷贝完成时重新启动。drain 检查与它比较，
	// 使 drain 宽限期的度量基准与空闲超时一致。
	idleSince := time.Now()
	resetIdle := func() {
		idleSince = time.Now()
		resetTimer(timer, idleTimeout)
	}

	// drain 计时器：周期性采样而不是在每次状态变化时重新武装，因为 slot 标记
	// （drainWhen）由健康检查循环异步翻转。tick 取 drainIdle 的一个分数，
	// 因此进入空闲后 drain 会在约 drainIdle..drainIdle+tick 内触发。
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
				// 排空两个 goroutine 的结果，使它们能干净地退出。
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
			// 排空两个 goroutine 的结果，使它们能干净地退出。
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
	// 实际不可达：循环只在 done == 2 时退出，而所有把 done 递增到 2 的路径
	// 都会在 select 内直接返回。此处的 return 仅仅是为了满足编译器的
	// 控制流分析。
	return Result{Err: firstErr}
}
