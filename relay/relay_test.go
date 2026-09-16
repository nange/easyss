package relay

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// blockPair 返回两个会阻塞到 onClose 触发的拷贝函数，以及 onClose 回调本身；
// 该回调恰好关闭一次 block 通道，使拷贝 goroutine 在中继终止后退出。
func blockPair() (func(func()) error, func(func()) error, func()) {
	block := make(chan struct{})
	var once sync.Once
	onClose := func() { once.Do(func() { close(block) }) }
	copyBlock := func(signal func()) error {
		<-block
		return nil
	}
	return copyBlock, copyBlock, onClose
}

func TestBidirectionalCompletion(t *testing.T) {
	closed := 0
	onClose := func() { closed++ }
	result := Bidirectional(time.Minute, onClose,
		func(signal func()) error { return nil },
		func(signal func()) error { return nil },
	)
	if result.Err != nil || result.TimedOut || result.Drained {
		t.Fatalf("unexpected result: %+v", result)
	}
	if closed != 1 {
		t.Fatalf("onClose called %d times, want 1", closed)
	}
}

func TestBidirectionalFirstError(t *testing.T) {
	sentinel := errors.New("copy failed")
	closed := 0
	_, copy2, onClose := blockPair()
	result := Bidirectional(time.Minute, func() { closed++; onClose() },
		func(signal func()) error { return sentinel },
		copy2,
	)
	if !errors.Is(result.Err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", result.Err)
	}
	if result.TimedOut || result.Drained {
		t.Fatalf("unexpected flags: %+v", result)
	}
	if closed != 1 {
		t.Fatalf("onClose called %d times, want 1", closed)
	}
}

func TestBidirectionalIdleTimeout(t *testing.T) {
	copy1, copy2, onClose := blockPair()
	closed := 0
	start := time.Now()
	result := Bidirectional(50*time.Millisecond, func() { closed++; onClose() }, copy1, copy2)
	if !result.TimedOut {
		t.Fatalf("expected TimedOut, got %+v", result)
	}
	if result.Drained {
		t.Fatal("plain Bidirectional must never report Drained")
	}
	if closed != 1 {
		t.Fatalf("onClose called %d times, want 1", closed)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timeout took %v, want ~50ms", elapsed)
	}
}

// TestBidirectionalWithDrainFires 验证 drain 机制会在 drainWhen 为 true 时
// 关闭一个空闲超过 drainIdle 的中继。
func TestBidirectionalWithDrainFires(t *testing.T) {
	copy1, copy2, onClose := blockPair()
	closed := 0
	start := time.Now()
	result := BidirectionalWithDrain(time.Minute, func() bool { return true }, 100*time.Millisecond,
		func() { closed++; onClose() }, copy1, copy2)
	if !result.Drained || !result.TimedOut {
		t.Fatalf("expected drained+timed out result, got %+v", result)
	}
	if closed != 1 {
		t.Fatalf("onClose called %d times, want 1", closed)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("drain took %v, want ~100ms", elapsed)
	}
}

// TestBidirectionalWithDrainNotFiredWithoutSlotMark 验证当 drainWhen 报告
// slot 未到淘汰时机时 drain 永不触发；中继只在某个拷贝出错时结束。
func TestBidirectionalWithDrainNotFiredWithoutSlotMark(t *testing.T) {
	_, copy2, onClose := blockPair()
	closed := 0
	start := time.Now()
	// copy1 持续发送 300ms 的活动信号（远超 drainIdle）然后出错；
	// 没有 slot 标记时，中继必须撑过整个窗口。
	result := BidirectionalWithDrain(time.Minute, func() bool { return false }, 100*time.Millisecond,
		func() { closed++; onClose() },
		func(signal func()) error {
			deadline := time.Now().Add(300 * time.Millisecond)
			for time.Now().Before(deadline) {
				signal()
				time.Sleep(10 * time.Millisecond)
			}
			return errors.New("copy done")
		},
		copy2,
	)
	if result.Drained || result.TimedOut {
		t.Fatalf("expected a plain copy-error result, got %+v", result)
	}
	if result.Err == nil {
		t.Fatal("expected the copy error")
	}
	if closed != 1 {
		t.Fatalf("onClose called %d times, want 1", closed)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("relay took %v, want ~300ms", elapsed)
	}
}

// TestBidirectionalWithDrainResetByActivity 验证持续有流量的流永远不会被
// drain：活动会重新启动空闲计时，因此即使 drainWhen 为 true，中继也能
// 远超 drainIdle 存活，只在某个拷贝出错时结束。
func TestBidirectionalWithDrainResetByActivity(t *testing.T) {
	copyBlock, _, onCloseBlock := blockPair()
	closed := 0
	result := BidirectionalWithDrain(time.Minute, func() bool { return true }, 100*time.Millisecond,
		func() { closed++; onCloseBlock() },
		func(signal func()) error {
			// 持续流动 400ms，远超 drainIdle。
			deadline := time.Now().Add(400 * time.Millisecond)
			for time.Now().Before(deadline) {
				signal()
				time.Sleep(10 * time.Millisecond)
			}
			return errors.New("copy done")
		},
		copyBlock,
	)
	if result.Drained {
		t.Fatal("expected not drained while activity keeps flowing")
	}
	if result.Err == nil {
		t.Fatal("expected the copy error")
	}
	if closed != 1 {
		t.Fatalf("onClose called %d times, want 1", closed)
	}
}
