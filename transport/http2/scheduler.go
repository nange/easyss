package http2

import (
	"math"
	"sync"
	"sync/atomic"

	"github.com/nange/easyss/v3/stats"
)

// slotScheduler maps new streams onto slots (least-active, health-aware)
// and manages the live slot set: growth under load, shrink on idle, and
// swap-remove of retired slots. Slot health state itself is owned by
// slotLifecycle; the scheduler only consumes the eligibility signals.
type slotScheduler struct {
	slots         []*transportSlot // pre-allocated and initialized to maxSlots
	liveCount     atomic.Int32     // number of currently live slots (0..maxSlots)
	maxSlots      int
	threshold     int32
	prioritySlots int // number of priority slots (0..prioritySlots-1)
	bulkThreshold int32
	mu            sync.RWMutex // protects slot retire (shrink) and grow; RLock protects stream assignment
}

func newScheduler(maxSlots int, slots []*transportSlot, threshold int32, prioritySlots int) *slotScheduler {
	return &slotScheduler{
		slots:         slots,
		maxSlots:      maxSlots,
		threshold:     threshold,
		prioritySlots: prioritySlots,
		bulkThreshold: threshold * 2,
	}
}

// pick returns the slot a new stream should use: priority streams prefer
// priority slots, bulk streams prefer the bulk range, each falling back to
// the other range when its own is exhausted.
func (s *slotScheduler) pick(highPriority bool) *transportSlot {
	if highPriority && s.prioritySlots > 0 {
		slot := s.leastActiveInRange(0, s.prioritySlots)
		if slot == nil || slot.active.Load() >= s.threshold {
			stats.RecordPriorityFallback()
			slot = s.leastActiveInRange(s.prioritySlots, int(s.liveCount.Load()))
		}
		return slot
	}

	slot := s.leastActiveInRange(s.prioritySlots, int(s.liveCount.Load()))
	if slot == nil || slot.active.Load() >= s.bulkThreshold {
		stats.RecordBulkFallback()
		slot = s.leastActiveInRange(0, s.prioritySlots)
	}
	return slot
}

// leastActiveInRange returns the slot in [start,end) with the fewest active
// streams, preferring healthy slots, then slots without heavy streams, then
// expiring ones, and only falling back to degraded ones when nothing else is
// available:
//   - a heavy stream monopolizes the connection's TCP window, so a new
//     stream sharing that slot is dragged down together with it (TCP
//     head-of-line blocking under packet loss);
//   - an expiring slot is due for connection rotation, but rotation overdue
//     says nothing about the connection's health: routing new streams onto
//     it keeps the connection alive until its stream gap, which spreads the
//     re-dials of a same-batch expiry instead of clustering them, so it is
//     preferred over a degraded slot;
//   - a degraded slot already proved persistently low throughput, so it is
//     avoided unless it is the only option left.
func (s *slotScheduler) leastActiveInRange(start, end int) *transportSlot {
	live := int(s.liveCount.Load())
	if live == 0 {
		return s.slots[0]
	}
	if end > live {
		end = live
	}
	if start >= end {
		start = 0
		end = live
	}
	passes := []struct {
		skipHeavy    bool
		skipDegraded bool
		skipExpiring bool
	}{
		{true, true, true},   // healthy slots
		{false, true, true},  // heavy but not degraded/expiring
		{false, true, false}, // expiring but not degraded: rotation overdue, connection likely still fine
		{false, false, false},
	}
	var best *transportSlot
	for _, p := range passes {
		var min int32 = math.MaxInt32
		for i := start; i < end; i++ {
			sl := s.slots[i]
			if !sl.eligible(p.skipHeavy, p.skipDegraded, p.skipExpiring) {
				continue
			}
			if a := sl.active.Load(); a < min {
				best, min = sl, a
			}
		}
		if best != nil {
			return best
		}
	}
	return s.slots[0]
}

// growRange returns the slot range a new stream of the given class would be
// scheduled onto, plus the saturation threshold used to decide whether one
// more slot is needed: priority streams prefer [0, prioritySlots), bulk
// streams prefer [prioritySlots, live). Like pick, both fall back to the
// whole live range when their own range is empty — in particular, bulk
// streams schedule over the entire pool while live < prioritySlots, so a
// pure bulk workload must be able to grow the pool instead of piling onto
// the initial connections forever.
func (s *slotScheduler) growRange(highPriority bool, live int32) (start, end, thresh int32) {
	thresh = s.threshold
	start, end = 0, live
	if highPriority && s.prioritySlots > 0 {
		end = int32(s.prioritySlots)
		if end > live {
			end = live
		}
	} else if s.prioritySlots > 0 {
		start = int32(s.prioritySlots)
		thresh = s.bulkThreshold
		if start >= end {
			// The bulk range is still empty (live <= prioritySlots): bulk
			// streams fall back onto the whole live range, so growth must
			// use that same range.
			start = 0
		}
	}
	return start, end, thresh
}

// grow activates one more live slot (up to maxSlots) when every eligible
// slot that a new stream of this class would use is at or above the
// threshold. Uses double-checked locking.
func (s *slotScheduler) grow(highPriority bool) {
	live := s.liveCount.Load()
	if int(live) >= s.maxSlots {
		return
	}

	start, end, thresh := s.growRange(highPriority, live)
	if live > 0 {
		if start >= end {
			return
		}
		if !s.needsMore(start, end, thresh) {
			return
		}
	}

	// All eligible slots in range are at or above threshold — try to grow
	// under lock.
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring the lock.
	live = s.liveCount.Load()
	if int(live) >= s.maxSlots {
		return
	}
	start, end, thresh = s.growRange(highPriority, live)
	if live > 0 {
		if start >= end {
			return
		}
		if !s.needsMore(start, end, thresh) {
			return
		}
	}

	// On first activation, start with 2 connections for better initial throughput,
	// since typical web browsing generates >8 concurrent streams.
	// Falls back to 1 when maxSlots is 1.
	if live == 0 && s.maxSlots >= 2 {
		s.liveCount.Add(2)
	} else {
		s.liveCount.Add(1)
	}
}

// needsMore reports whether the range [start,end) needs one more live slot:
// every slot a new stream would actually use is at or above the threshold.
// Heavy, degraded and expiring slots are skipped — a new stream avoids
// them, so a heavy slot hosting a single download must not block growing
// more connections. A range with no eligible slot at all also grows, since
// new streams then fall back onto heavy/degraded slots and deserve a fresh
// connection.
func (s *slotScheduler) needsMore(start, end, thresh int32) bool {
	for i := start; i < end; i++ {
		sl := s.slots[i]
		if !sl.eligible(true, true, true) {
			continue
		}
		if sl.active.Load() < thresh {
			return false
		}
	}
	return true
}

// shrinkIdleLocked retires every idle slot (active==0) from liveCount,
// swap-removing each to the end. Caller must hold s.mu.
func (s *slotScheduler) shrinkIdleLocked() {
	for s.removeIdleLocked() {
	}
}

// removeIdleLocked swap-removes the first idle slot from liveCount.
// Returns false when no idle slot remains. Caller must hold s.mu.
func (s *slotScheduler) removeIdleLocked() bool {
	live := int(s.liveCount.Load())
	for i := 0; i < live; i++ {
		if s.slots[i].active.Load() != 0 {
			continue
		}
		s.removeAtLocked(i, live)
		return true
	}
	return false
}

// removeAtLocked swap-removes the slot at position i from liveCount.
// Caller must hold s.mu.
func (s *slotScheduler) removeAtLocked(i, live int) {
	last := live - 1
	if i != last {
		s.slots[i], s.slots[last] = s.slots[last], s.slots[i]
	}
	s.liveCount.Add(-1)
}

// remove swaps the slot out of liveCount (swap-remove) if it is still live
// and not hosting streams, and reports whether the removal happened.
// Streams are re-checked under the lock so a concurrent Open cannot be
// stranded.
func (s *slotScheduler) remove(sl *transportSlot) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sl.active.Load() != 0 {
		return false
	}
	live := int(s.liveCount.Load())
	for i := 0; i < live; i++ {
		if s.slots[i] != sl {
			continue
		}
		s.removeAtLocked(i, live)
		return true
	}
	return false
}
