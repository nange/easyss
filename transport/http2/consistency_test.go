package http2

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestStatsConnsStatusConsistencyUnderShrink stresses the scheduler with a
// shrinker goroutine (simulating closeIdleLoop) while a stats reader
// goroutine (simulating /stats polling) renders conns_status. It fails if the
// rendered entry count ever exceeds the concurrently reported Conns value,
// or if the rendered indices are not consecutive from 0.
func TestStatsConnsStatusConsistencyUnderShrink(t *testing.T) {
	slots := make([]*transportSlot, 6)
	for i := range slots {
		slots[i] = &transportSlot{idx: i}
	}
	sch := newScheduler(6, slots, 2, 1)
	sch.liveCount.Store(6)

	var over atomic.Int64
	var badIdx atomic.Int64
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
			idxs := parseIndices(s)
			if len(idxs) > live {
				over.Add(int64(len(idxs) - live))
			}
			for k, id := range idxs {
				if id != k {
					badIdx.Add(1)
					break
				}
			}
			reads.Add(1)
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(done)
	wg.Wait()
	t.Logf("reads=%d over_by_total=%d bad_idx_total=%d", reads.Load(), over.Load(), badIdx.Load())
	if over.Load() > 0 {
		t.Fatalf("conns_status rendered more entries than Conns: over=%d", over.Load())
	}
	if badIdx.Load() > 0 {
		t.Fatalf("conns_status indices are not consecutive from 0: bad=%d", badIdx.Load())
	}
}

// parseIndices extracts the leading "<index>:" of each entry, verifying the
// array-like shape at the same time.
func parseIndices(s string) []int {
	if s == "[]" {
		return nil
	}
	body := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	parts := strings.Split(body, ", ")
	idxs := make([]int, 0, len(parts))
	for _, p := range parts {
		colon := strings.IndexByte(p, ':')
		n, err := strconv.Atoi(p[:colon])
		if err != nil {
			panic("malformed entry: " + p)
		}
		idxs = append(idxs, n)
	}
	return idxs
}
