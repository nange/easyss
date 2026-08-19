package http2

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestStatsConnsStatusConsistencyUnderShrink stresses the scheduler with a
// shrinker goroutine (simulating closeIdleLoop) while a stats reader
// goroutine (simulating /stats polling) renders conns_status. It fails if the
// rendered entry count ever exceeds the concurrently reported Conns value.
func TestStatsConnsStatusConsistencyUnderShrink(t *testing.T) {
	slots := make([]*transportSlot, 6)
	for i := range slots {
		slots[i] = &transportSlot{idx: i}
	}
	sch := newScheduler(6, slots, 2, 1)
	sch.liveCount.Store(6)

	var over atomic.Int64
	var reads atomic.Int64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			sch.mu.Lock()
			sch.shrinkIdleLocked()
			sch.mu.Unlock()
			// Re-grow like new streams arriving.
			sch.grow(false)
		}
	}()

	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			live := int(sch.liveCount.Load())
			s := slotStatusString(sch, live)
			n := countEntries(s)
			if n > live {
				over.Add(int64(n - live))
			}
			reads.Add(1)
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(done)
	wg.Wait()
	t.Logf("reads=%d over_by_total=%d", reads.Load(), over.Load())
	if over.Load() > 0 {
		t.Fatalf("conns_status rendered more entries than Conns: over=%d", over.Load())
	}
}

func countEntries(s string) int {
	if s == "[]" {
		return 0
	}
	n := 1
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			n++
		}
	}
	return n
}
