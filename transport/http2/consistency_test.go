package http2

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/transport"
)

// TestStatsConnsStatusConsistencyUnderShrink stresses the scheduler with a
// shrinker goroutine (simulating closeIdleLoop) while a stats reader
// goroutine (simulating /stats polling) renders each pool's conns_status.
// It fails if a rendered entry count ever exceeds the concurrently reported
// per-pool Conns value, or if the rendered indices are not consecutive from
// 0 in either pool.
func TestStatsConnsStatusConsistencyUnderShrink(t *testing.T) {
	slots := make([]*transportSlot, 6)
	for i := range slots {
		slots[i] = &transportSlot{idx: i}
	}
	sch := newScheduler(6, slots, 2, 1)
	sch.priority.liveCount.Store(1)
	sch.bulk.liveCount.Store(5)

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
			// Render under the scheduler read lock, exactly like the
			// production Stats() snapshot: shrink/grow swap-remove slots
			// under the write lock, so an unlocked render would race with
			// the array swaps.
			sch.mu.RLock()
			pLive := int(sch.priority.liveCount.Load())
			bLive := int(sch.bulk.liveCount.Load())
			pStr := slotStatusString(sch.priority, pLive)
			bStr := slotStatusString(sch.bulk, bLive)
			sch.mu.RUnlock()
			pIdxs := parseIndices(pStr)
			bIdxs := parseIndices(bStr)
			if len(pIdxs) > pLive {
				over.Add(int64(len(pIdxs) - pLive))
			}
			if len(bIdxs) > bLive {
				over.Add(int64(len(bIdxs) - bLive))
			}
			for k, id := range pIdxs {
				if id != k {
					badIdx.Add(1)
					break
				}
			}
			for k, id := range bIdxs {
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

// TestGrowEventRingOrderAndCap verifies the growth-event ring: newest
// first, bounded at maxGrowEvents, carrying the triggering request's
// endpoint and target.
func TestGrowEventRingOrderAndCap(t *testing.T) {
	slots := make([]*transportSlot, 4)
	for i := range slots {
		slots[i] = &transportSlot{idx: i}
	}
	tr := &HTTP2Transport{sched: newScheduler(4, slots, 4, 2)}

	for i := range maxGrowEvents + 4 {
		tr.recordGrowEvent("bulk", int32(i), transport.OpenRequest{
			Endpoint: sharedconfig.EndpointUDP,
			Target:   "8.8.8.8:53",
		})
	}

	evs := tr.Stats().GrowEvents
	if len(evs) != maxGrowEvents {
		t.Fatalf("GrowEvents = %d, want %d (ring bound)", len(evs), maxGrowEvents)
	}
	// Newest first: the last recorded event (live = maxGrowEvents+3) heads
	// the snapshot, the oldest surviving (live = 4) tails it.
	if evs[0].Live != maxGrowEvents+3 {
		t.Fatalf("head event live = %d, want %d (newest first)", evs[0].Live, maxGrowEvents+3)
	}
	if evs[0].Pool != "bulk" || evs[0].Endpoint != sharedconfig.EndpointUDP || evs[0].Target != "8.8.8.8:53" {
		t.Fatalf("head event fields wrong: %+v", evs[0])
	}
	if evs[len(evs)-1].Live != 4 {
		t.Fatalf("tail event live = %d, want 4 (oldest surviving)", evs[len(evs)-1].Live)
	}
}

// TestGrowEventRingConcurrent stresses the growth-event ring: a producer
// goroutine recording events while a reader goroutine snapshots Stats() —
// must stay race-free and never exceed the ring bound.
func TestGrowEventRingConcurrent(t *testing.T) {
	slots := make([]*transportSlot, 4)
	for i := range slots {
		slots[i] = &transportSlot{idx: i}
	}
	tr := &HTTP2Transport{sched: newScheduler(4, slots, 4, 2)}

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
			tr.recordGrowEvent("bulk", 3, transport.OpenRequest{
				Endpoint: sharedconfig.EndpointTCP,
				Target:   "1.2.3.4:53",
			})
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
			_ = tr.Stats()
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(done)
	wg.Wait()

	if got := len(tr.Stats().GrowEvents); got > maxGrowEvents {
		t.Fatalf("GrowEvents = %d, want <= %d", got, maxGrowEvents)
	}
}
