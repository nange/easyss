package relay

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// blockPair returns two copy functions that block until onClose fires, and
// the onClose callback itself, which closes the block channel exactly once so
// the copy goroutines exit after the relay terminates.
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

// TestBidirectionalWithDrainFires verifies the drain mechanism closes a
// relay that has been idle beyond drainIdle while drainWhen is true.
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

// TestBidirectionalWithDrainNotFiredWithoutSlotMark verifies the drain never
// fires while drainWhen reports the slot is not due for eviction; the relay
// only ends when a copy errors.
func TestBidirectionalWithDrainNotFiredWithoutSlotMark(t *testing.T) {
	_, copy2, onClose := blockPair()
	closed := 0
	start := time.Now()
	// copy1 signals activity for 300ms (well beyond drainIdle) then errors;
	// without the slot mark the relay must survive that whole window.
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

// TestBidirectionalWithDrainResetByActivity verifies that a stream which
// keeps flowing is never drained: activity restarts the idle clock, so even
// with drainWhen true the relay survives far beyond drainIdle and only ends
// when a copy errors.
func TestBidirectionalWithDrainResetByActivity(t *testing.T) {
	copyBlock, _, onCloseBlock := blockPair()
	closed := 0
	result := BidirectionalWithDrain(time.Minute, func() bool { return true }, 100*time.Millisecond,
		func() { closed++; onCloseBlock() },
		func(signal func()) error {
			// Keep flowing for 400ms, far beyond drainIdle.
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
