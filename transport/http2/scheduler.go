package http2

import (
	"math"
	"sync"
	"sync/atomic"

	"github.com/nange/easyss/v3/stats"
)

// slotScheduler maps new streams onto slots with a priority-aware, tiered
// pressure scheduler and manages the live slot set: growth under load,
// shrink on idle, and swap-remove of retired slots. Slot health state
// itself is owned by slotLifecycle; the scheduler only consumes the
// eligibility signals (heavy/degraded/expiring marks).
//
// Scheduling model — priority × tier:
//
//   - Streams are classed by priority. Priority streams (interactive
//     destinations, see stream.go) prefer the priority range
//     [0, prioritySlots) and measure saturation against threshold; bulk
//     streams prefer the bulk range [prioritySlots, live) and measure
//     saturation against bulkThreshold = 2×threshold. Each class falls back
//     to the whole pool when its own range is saturated.
//
//   - Within a range, slots are ordered by health tiers (see slotTierOf):
//     active (healthy) slots host new streams first. Once every active slot
//     reached the class's pressure base, expiring slots take over (rotation
//     overdue but the connection is still healthy) up to base/2 streams
//     each; heavy slots (healthy connection monopolized by heavy streams)
//     and degraded slots (confirmed slow) follow, up to base/4 each. Tier
//     caps double whenever the active layer is pushed to the next
//     power-of-two multiple of the base, so a fully saturated pool keeps
//     spreading load instead of piling onto one connection.
//
//   - Growth fires only when every tier of the class's ranges is saturated:
//     existing connections — including negative ones — are squeezed first,
//     and only then is a new connection dialed, avoiding needless TLS
//     re-dials under light overload.
type slotScheduler struct {
	slots         []*transportSlot // pre-allocated and initialized to maxSlots
	liveCount     atomic.Int32     // number of currently live slots (0..maxSlots)
	maxSlots      int
	threshold     int32 // pressure base for priority streams
	prioritySlots int   // number of priority slots (0..prioritySlots-1)
	bulkThreshold int32 // pressure base for bulk streams (2×threshold)
	mu            sync.RWMutex
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

// slotTier classifies a slot by its most negative health signal. The tiers
// are ordered from best to worst: a slot belongs to exactly one tier, and
// tieredSelect walks them in this order:
//
//	tierActive    — no marks: the connection is healthy and preferred;
//	tierExpiring  — rotation overdue, but the connection is likely still
//	                fine: routing new streams onto it keeps it alive until
//	                its stream gap, spreading same-batch re-dials instead of
//	                clustering them;
//	tierHeavy     — heavy streams monopolize the TCP window, dragging any
//	                sharing stream down with them (head-of-line blocking
//	                under loss), yet the connection itself is healthy;
//	tierDegraded  — the connection proved persistently low throughput, the
//	                worst candidate, used only as a last resort.
type slotTier int

const (
	tierActive slotTier = iota
	tierExpiring
	tierHeavy
	tierDegraded
)

// slotTierOf returns the tier a slot currently belongs to. Heavy+expiring
// slots classify as heavy (the heavier mark wins), any degraded combination
// classifies as degraded.
func slotTierOf(s *transportSlot) slotTier {
	if s.degraded.Load() {
		return tierDegraded
	}
	if s.heavy.Load() > 0 {
		return tierHeavy
	}
	if s.expiring.Load() {
		return tierExpiring
	}
	return tierActive
}

// negativeScore quantifies how many negative marks a slot carries, used as
// the secondary ordering key within a tier: among equally loaded slots the
// one with fewer negative states wins. Weights follow the tier order:
// degraded 4 > heavy 2 > expiring 1.
func negativeScore(s *transportSlot) int32 {
	var score int32
	if s.degraded.Load() {
		score += 4
	}
	if s.heavy.Load() > 0 {
		score += 2
	}
	if s.expiring.Load() {
		score += 1
	}
	return score
}

// preferredRange returns the slot range a new stream of the given class
// prefers, plus the class's pressure base: priority streams prefer
// [0, prioritySlots) and saturate at threshold, bulk streams prefer
// [prioritySlots, live) and saturate at bulkThreshold. Like pick, both
// classes fall back to the whole live range when their own range is
// empty — in particular, bulk streams schedule over the entire pool while
// live < prioritySlots, so a pure bulk workload must be able to grow the
// pool instead of piling onto the initial connections forever.
func (s *slotScheduler) preferredRange(highPriority bool) (start, end int, base int32) {
	live := int(s.liveCount.Load())
	start, end = 0, live
	base = s.bulkThreshold
	if highPriority && s.prioritySlots > 0 {
		end = s.prioritySlots
		if end > live {
			end = live
		}
		base = s.threshold
	} else if s.prioritySlots > 0 {
		start = s.prioritySlots
		if start >= end {
			// The bulk range is still empty (live <= prioritySlots): bulk
			// streams fall back onto the whole live range.
			start = 0
		}
	}
	return start, end, base
}

// pick returns the slot a new stream should use. The stream's class
// (priority/bulk) picks its preferred range and pressure base; the range is
// searched with the tiered pressure scheduler. When every tier of the
// preferred range is saturated, the whole pool is searched once more (the
// other range may still host healthy slots). The result is never nil: with
// no live slots the first pre-allocated slot is returned.
func (s *slotScheduler) pick(highPriority bool) *transportSlot {
	start, end, base := s.preferredRange(highPriority)
	slot, saturated := s.tieredSelect(start, end, base)
	if saturated {
		// The preferred range is fully saturated: give the other range a
		// chance before settling for the fallback slot.
		if highPriority {
			stats.RecordPriorityFallback()
		} else {
			stats.RecordBulkFallback()
		}
		slot, _ = s.tieredSelect(0, int(s.liveCount.Load()), base)
	}
	return slot
}

// tieredSelect picks the best slot in [start,end) for a new stream under
// the pressure scheduler, returning (slot, saturated). saturated is true
// when no tier has capacity left, in which case slot is the fallback result
// (see below).
//
// The search walks the tiers in order of desirability — active first, then
// expiring, heavy and degraded — and within a tier prefers the slot with
// the fewest active streams, breaking ties by negativeScore. A tier only
// accepts a slot whose active count is below the tier's capacity, which
// scales with the pressure level (see pressureLevel and tierCap). Once
// every tier is full, the fallback "keeps piling" onto the least-loaded
// healthy slot (or the least-loaded slot overall when none is healthy) with
// no cap: that pushes the active layer toward the next pressure level,
// where tier capacities double and the spill-over resumes.
func (s *slotScheduler) tieredSelect(start, end int, base int32) (*transportSlot, bool) {
	live := int(s.liveCount.Load())
	if live == 0 {
		return s.slots[0], false
	}
	if end > live {
		end = live
	}
	if start >= end {
		start, end = 0, live
	}

	level := s.pressureLevel(start, end, base)

	// consider picks the least-active, least-negative slot of one tier
	// within the current capacity; it reports whether such a slot exists.
	var best *transportSlot
	consider := func(tier slotTier) bool {
		cap := s.tierCap(tier, level, base)
		if cap <= 0 {
			return false
		}
		best = nil
		var bestActive int32 = math.MaxInt32
		var bestNeg int32 = math.MaxInt32
		for i := start; i < end; i++ {
			sl := s.slots[i]
			if slotTierOf(sl) != tier {
				continue
			}
			a := sl.active.Load()
			if a >= cap {
				continue
			}
			neg := negativeScore(sl)
			if a < bestActive || (a == bestActive && neg < bestNeg) {
				best, bestActive, bestNeg = sl, a, neg
			}
		}
		return best != nil
	}

	if level == 0 {
		// Only the active tier has capacity while the active layer is
		// below the base: healthy slots are preferred and negative ones
		// are left alone.
		if consider(tierActive) {
			return best, false
		}
		// Concurrent window: the active layer filled up between the level
		// computation and the search — degrade to level 1 and continue.
		level = 1
	}
	if consider(tierExpiring) {
		stats.RecordTierExpiring()
		return best, false
	}
	if consider(tierHeavy) {
		stats.RecordTierHeavy()
		return best, false
	}
	if consider(tierDegraded) {
		stats.RecordTierDegraded()
		return best, false
	}

	// Every tier is at capacity: fall back to piling onto the least-loaded
	// healthy slot (the "back to active" step of the model), or onto the
	// least-loaded slot overall when no healthy slot exists.
	if sl := s.leastActiveHealthy(start, end); sl != nil {
		return sl, true
	}
	return s.leastActiveInRange(start, end), true
}

// pressureLevel derives the current pressure level from the least-loaded
// active (healthy) slot in [start,end) against the class's pressure base:
//
//	level 0: minActive < base — the active layer still has capacity, no
//	         lower tier is enabled;
//	level k (k>=1): minActive ∈ [2^(k-1)*base, 2^k*base) — every active slot
//	         is at or beyond 2^(k-1)*base streams; tier capacities for
//	         expiring/heavy/degraded scale with k (see tierCap).
//
// With no healthy slot at all (the active layer is "full" by definition),
// the level degrades to the whole-range minimum so the lower tiers engage
// immediately, and it is clamped to at least level 1.
func (s *slotScheduler) pressureLevel(start, end int, base int32) int32 {
	activeMin, hasActive := s.minActiveInTier(start, end, tierActive)
	if hasActive {
		if activeMin < base {
			return 0
		}
		return 1 + floorLog2(activeMin/base)
	}
	poolMin := s.minActiveInRange(start, end)
	if poolMin < base {
		poolMin = base
	}
	return 1 + floorLog2(poolMin/base)
}

// floorLog2 returns floor(log2(v)) for v > 0.
func floorLog2(v int32) int32 {
	var n int32
	for v > 1 {
		v >>= 1
		n++
	}
	return n
}

// tierCap returns the stream capacity of one tier at the given pressure
// level: a slot of that tier accepts a new stream only while its active
// count stays below the capacity.
//
//	level 0: only the active tier has capacity, cap = base;
//	level k>=1: expiring    = 2^(k-2)*base  (k=1 → base/2)
//	            heavy       = 2^(k-3)*base  (k=1 → base/4, k=2 → base/2)
//	            degraded    = same as heavy
//
// Every level-up doubles all lower-tier capacities: the model first spills
// onto the negative tiers, then piles back onto the active layer until it
// doubles, then the lower-tier capacities double and the spill resumes —
// cycling until streams end and the load naturally falls back. Note that
// for a priority stream (base=threshold) a level-1 heavy/degraded capacity
// of base/4 = 1 is effectively unusable (such slots always host >= 1 active
// stream), which is intended: priority streams only spill onto negative
// slots under real pressure. Extreme levels shift beyond int32 range; the
// resulting negative capacity is treated as "no capacity" by callers.
func (s *slotScheduler) tierCap(tier slotTier, level, base int32) int32 {
	if level == 0 {
		if tier == tierActive {
			return base
		}
		return 0
	}
	switch tier {
	case tierExpiring:
		if level == 1 {
			return base / 2
		}
		return base << (level - 2)
	case tierHeavy, tierDegraded:
		if level == 1 {
			return base / 4
		}
		if level == 2 {
			return base / 2
		}
		return base << (level - 3)
	default:
		// tierActive is never actively searched at level >= 1: every
		// active slot is at or beyond the current threshold by definition,
		// so none would pass the capacity check. "Piling back onto the
		// active layer" is the fallback path in tieredSelect.
		return 0
	}
}

// minActiveInTier returns the smallest active-stream count among slots of
// the given tier in [start,end), and whether such a slot exists.
func (s *slotScheduler) minActiveInTier(start, end int, tier slotTier) (int32, bool) {
	var min int32 = math.MaxInt32
	found := false
	for i := start; i < end; i++ {
		sl := s.slots[i]
		if slotTierOf(sl) != tier {
			continue
		}
		if a := sl.active.Load(); a < min {
			min = a
		}
		found = true
	}
	return min, found
}

// minActiveInRange returns the smallest active-stream count over all slots
// in [start,end); 0 when the range holds no slot.
func (s *slotScheduler) minActiveInRange(start, end int) int32 {
	var min int32 = math.MaxInt32
	for i := start; i < end; i++ {
		if a := s.slots[i].active.Load(); a < min {
			min = a
		}
	}
	if min == math.MaxInt32 {
		return 0
	}
	return min
}

// leastActiveHealthy returns the healthy (no marks) slot in [start,end)
// with the fewest active streams, or nil when none exists.
func (s *slotScheduler) leastActiveHealthy(start, end int) *transportSlot {
	var best *transportSlot
	var min int32 = math.MaxInt32
	for i := start; i < end; i++ {
		sl := s.slots[i]
		if slotTierOf(sl) != tierActive {
			continue
		}
		if a := sl.active.Load(); a < min {
			best, min = sl, a
		}
	}
	return best
}

// leastActiveInRange returns the slot in [start,end) with the fewest active
// streams — the final uncapped fallback of the pressure scheduler; among
// equally loaded slots the one with fewer negative marks wins. With no live
// slots the first pre-allocated slot is returned.
func (s *slotScheduler) leastActiveInRange(start, end int) *transportSlot {
	live := int(s.liveCount.Load())
	if live == 0 {
		return s.slots[0]
	}
	if end > live {
		end = live
	}
	if start >= end {
		start, end = 0, live
	}
	var best *transportSlot
	var min int32 = math.MaxInt32
	var minNeg int32 = math.MaxInt32
	for i := start; i < end; i++ {
		sl := s.slots[i]
		a := sl.active.Load()
		neg := negativeScore(sl)
		if a > min || (a == min && neg >= minNeg) {
			continue
		}
		best, min, minNeg = sl, a, neg
	}
	return best
}

// saturatedIn reports whether the tiered scheduler has no capacity left in
// [start,end) for a stream of the given base — i.e. tieredSelect would take
// its uncapped fallback path. Used by grow to decide when a new connection
// is truly needed.
func (s *slotScheduler) saturatedIn(start, end int, base int32) bool {
	_, saturated := s.tieredSelect(start, end, base)
	return saturated
}

// grow activates one more live slot (up to maxSlots), but only when every
// tier of the stream class's ranges is saturated: the pool first squeezes
// the remaining capacity of existing connections — including expiring,
// heavy and degraded ones — and only dials a fresh connection once nothing
// is left, so transient overload does not trigger needless TLS re-dials.
// Uses double-checked locking. On first activation (live == 0) two
// connections are activated at once for better initial throughput, since
// typical web browsing generates more than 8 concurrent streams; falls back
// to 1 when maxSlots is 1.
func (s *slotScheduler) grow(highPriority bool) {
	live := s.liveCount.Load()
	if int(live) >= s.maxSlots {
		return
	}

	start, end, base := s.preferredRange(highPriority)
	if live > 0 && !s.saturatedIn(start, end, base) {
		return
	}
	// The preferred range is saturated: before growing, check the whole
	// pool — the other range may still host capacity.
	if live > 0 && !s.saturatedIn(0, int(live), base) {
		return
	}

	// Every tier of every range is saturated — try to grow under lock.
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring the lock.
	live = s.liveCount.Load()
	if int(live) >= s.maxSlots {
		return
	}
	start, end, base = s.preferredRange(highPriority)
	if live > 0 && !s.saturatedIn(start, end, base) {
		return
	}
	if live > 0 && !s.saturatedIn(0, int(live), base) {
		return
	}

	if live == 0 && s.maxSlots >= 2 {
		s.liveCount.Add(2)
	} else {
		s.liveCount.Add(1)
	}
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
