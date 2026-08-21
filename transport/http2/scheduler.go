package http2

import (
	"math"
	"sync"
	"sync/atomic"

	"github.com/nange/easyss/v3/stats"
)

// slotScheduler maps new streams onto slots with a priority-aware, tiered
// pressure scheduler and manages the live slot sets: growth under load,
// shrink on idle, and swap-remove of retired slots. Slot health state
// itself is owned by slotLifecycle; the scheduler only consumes the
// eligibility signals (heavy/degraded/expiring marks).
//
// Scheduling model — two isolated pools × health tiers:
//
//   - Streams are classed by priority and each class owns a dedicated slot
//     pool, so a DNS query or download (bulk) activates its own connections
//     instead of sharing the interactive ones, and a burst of one class can
//     never starve the other:
//
//     priority pool: interactive destinations (see stream.go), pressure
//     base = threshold, at most PrioritySlotRatio×maxSlots connections;
//     bulk pool:     everything else, pressure base = bulkThreshold
//     (2×threshold), at most (1-ratio)×maxSlots connections.
//
//   - Within a pool, slots are ordered by health tiers (see slotTierOf):
//     active (healthy) slots host new streams first. Once every active slot
//     reached the pool's pressure base, expiring slots take over (rotation
//     overdue but the connection is still healthy) up to base/2 streams
//     each; heavy slots (healthy connection monopolized by heavy streams)
//     and degraded slots (confirmed slow) follow, up to base/4 each. Tier
//     caps double whenever the active layer is pushed to the next
//     power-of-two multiple of the base, so a fully saturated pool keeps
//     spreading load instead of piling onto one connection.
//
//   - Growth is per pool and fires only when every tier of that pool is
//     saturated: existing connections — including negative ones — are
//     squeezed first, and only then is a new connection dialed. When a pool
//     is at its connection cap and still saturated, pick borrows a healthy
//     slot from the other pool before settling for the uncapped fallback.
type slotScheduler struct {
	priority *slotPool // interactive streams, base = threshold
	bulk     *slotPool // everything else, base = bulkThreshold

	threshold     int32
	bulkThreshold int32
	mu            sync.RWMutex // protects pool growth/shrink; RLock protects stream assignment
}

// slotPool is one class's dedicated slot set. Slots are pre-allocated and
// initialized to maxSlots; liveCount grows lazily on first use (+2) and
// under load, and shrinks when slots go idle.
type slotPool struct {
	slots     []*transportSlot
	liveCount atomic.Int32 // number of currently live slots (0..maxSlots)
	maxSlots  int
	base      int32 // pressure base of this pool (threshold or bulkThreshold)
}

// newScheduler splits the pre-allocated slot array into the priority pool
// (first prioritySlots entries) and the bulk pool (the rest), keeping the
// total connection cap unchanged. The split honors PrioritySlotRatio via
// prioritySlots; both pools get at least one slot whenever maxSlots >= 2.
// Each pool renumbers its slots from 0, so a slot's stable idx is only
// meaningful within its own pool.
func newScheduler(maxSlots int, slots []*transportSlot, threshold int32, prioritySlots int) *slotScheduler {
	pMax := prioritySlots
	if pMax > maxSlots {
		pMax = maxSlots
	}
	if pMax < 1 {
		pMax = 1
	}
	bMax := maxSlots - pMax
	if bMax < 1 {
		// Degenerate split (maxSlots == 1 or ratio 1): give the bulk pool
		// the tail slot anyway; poolOf falls back to the priority pool when
		// the bulk pool is empty.
		bMax = 1
		if pMax > 1 {
			pMax = maxSlots - 1
		}
	}
	for i := 0; i < pMax; i++ {
		slots[i].idx = i
	}
	for i := 0; i < bMax; i++ {
		slots[pMax+i].idx = i
	}
	return &slotScheduler{
		priority: &slotPool{
			slots:    slots[:pMax],
			maxSlots: pMax,
			base:     threshold,
		},
		bulk: &slotPool{
			slots:    slots[pMax:],
			maxSlots: bMax,
			base:     threshold * 2,
		},
		threshold:     threshold,
		bulkThreshold: threshold * 2,
	}
}

// poolOf returns the pool a stream of the given class belongs to. When the
// bulk pool is empty (degenerate split) bulk streams share the priority
// pool, which then behaves like the single-pool model.
func (s *slotScheduler) poolOf(highPriority bool) *slotPool {
	if highPriority || s.bulk.maxSlots == 0 {
		return s.priority
	}
	return s.bulk
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

// pick returns the slot a new stream should use: the stream's class selects
// its own pool, searched with the tiered pressure scheduler. When every
// tier of the pool is saturated (and the pool is at its connection cap),
// the other pool is searched once more — its healthy slots are borrowed
// before piling onto a saturated connection. Even when the other pool is
// saturated too, its fallback slot may be far less loaded than ours (e.g.
// a heavy slot with 2 streams vs our piled-up healthy slot with 10), so it
// is borrowed whenever it is strictly less loaded. The result is never
// nil: with no live slots the first pre-allocated slot is returned.
func (s *slotScheduler) pick(highPriority bool) *transportSlot {
	pool := s.poolOf(highPriority)
	slot, saturated := pool.tieredSelect()
	if saturated {
		// The pool is fully saturated: give the other pool a chance before
		// settling for the uncapped fallback.
		if highPriority {
			stats.RecordPriorityFallback()
		} else {
			stats.RecordBulkFallback()
		}
		other, otherSat := s.otherPool(pool).tieredSelect()
		if !otherSat || other.active.Load() < slot.active.Load() {
			return other
		}
	}
	return slot
}

// otherPool returns the sibling of the given pool.
func (s *slotScheduler) otherPool(pool *slotPool) *slotPool {
	if pool == s.priority {
		return s.bulk
	}
	return s.priority
}

// tieredSelect picks the best slot of the pool for a new stream under the
// pressure scheduler, returning (slot, saturated). saturated is true when
// no tier has capacity left, in which case slot is the fallback result (see
// below). See tieredSelectAt for the search itself.
func (p *slotPool) tieredSelect() (*transportSlot, bool) {
	return p.tieredSelectAt(int(p.liveCount.Load()), true)
}

// saturatedIn reports whether the tiered scheduler has no capacity left in
// the pool — i.e. tieredSelect would take its uncapped fallback path. Used
// by grow to decide when a new connection is truly needed; unlike
// tieredSelect it does not record tier scheduling stats.
func (p *slotPool) saturatedIn(live int) bool {
	_, saturated := p.tieredSelectAt(live, false)
	return saturated
}

// tieredSelectAt is the tiered search over the first `live` slots:
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
func (p *slotPool) tieredSelectAt(live int, recordStats bool) (*transportSlot, bool) {
	if live == 0 {
		return p.slots[0], false
	}

	level := p.pressureLevel(live)

	// consider picks the least-active, least-negative slot of one tier
	// within the current capacity; it reports whether such a slot exists.
	var best *transportSlot
	consider := func(tier slotTier) bool {
		cap := tierCap(tier, level, p.base)
		if cap <= 0 {
			return false
		}
		best = nil
		var bestActive int32 = math.MaxInt32
		var bestNeg int32 = math.MaxInt32
		for i := 0; i < live; i++ {
			sl := p.slots[i]
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
		if recordStats {
			stats.RecordTierExpiring()
		}
		return best, false
	}
	if consider(tierHeavy) {
		if recordStats {
			stats.RecordTierHeavy()
		}
		return best, false
	}
	if consider(tierDegraded) {
		if recordStats {
			stats.RecordTierDegraded()
		}
		return best, false
	}

	// Every tier is at capacity: fall back to the least-loaded slot
	// overall, regardless of tier. Once the negative tiers' caps are
	// exhausted, the least-loaded slot may well be a heavy or degraded one
	// hosting far fewer streams than the piled-up healthy slots — piling
	// there keeps load balanced instead of stacking every stream onto one
	// crowded healthy connection (which is also what keeps the pressure
	// level honest).
	return p.leastActive(live), true
}

// pressureLevel derives the current pressure level from the least-loaded
// active (healthy) slot of the pool against the pool's pressure base:
//
//	level 0: minActive < base — the active layer still has capacity, no
//	         lower tier is enabled;
//	level k (k>=1): minActive ∈ [2^(k-1)*base, 2^k*base) — every active slot
//	         is at or beyond 2^(k-1)*base streams; tier capacities for
//	         expiring/heavy/degraded scale with k (see tierCap).
//
// With no healthy slot at all (the active layer is "full" by definition),
// the level degrades to the pool-wide minimum so the lower tiers engage
// immediately, and it is clamped to at least level 1.
func (p *slotPool) pressureLevel(live int) int32 {
	activeMin, hasActive := p.minActiveInTier(live, tierActive)
	if hasActive {
		if activeMin < p.base {
			return 0
		}
		return 1 + floorLog2(activeMin/p.base)
	}
	poolMin := p.minActiveInRange(live)
	if poolMin < p.base {
		poolMin = p.base
	}
	return 1 + floorLog2(poolMin/p.base)
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
func tierCap(tier slotTier, level, base int32) int32 {
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
// the given tier, and whether such a slot exists. Only the first `live`
// slots are considered.
func (p *slotPool) minActiveInTier(live int, tier slotTier) (int32, bool) {
	var min int32 = math.MaxInt32
	found := false
	for i := 0; i < live; i++ {
		sl := p.slots[i]
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

// minActiveInRange returns the smallest active-stream count over the first
// `live` slots; 0 when the range holds no slot.
func (p *slotPool) minActiveInRange(live int) int32 {
	var min int32 = math.MaxInt32
	for i := 0; i < live; i++ {
		if a := p.slots[i].active.Load(); a < min {
			min = a
		}
	}
	if min == math.MaxInt32 {
		return 0
	}
	return min
}

// leastActive returns the slot with the fewest active streams among the
// first `live` slots — the final uncapped fallback of the pressure
// scheduler; among equally loaded slots the one with fewer negative marks
// wins. With no live slots the first pre-allocated slot is returned.
func (p *slotPool) leastActive(live int) *transportSlot {
	if live == 0 {
		return p.slots[0]
	}
	var best *transportSlot
	var min int32 = math.MaxInt32
	var minNeg int32 = math.MaxInt32
	for i := 0; i < live; i++ {
		sl := p.slots[i]
		a := sl.active.Load()
		neg := negativeScore(sl)
		if a > min || (a == min && neg >= minNeg) {
			continue
		}
		best, min, minNeg = sl, a, neg
	}
	return best
}

// grow activates one more live slot of the pool (up to maxSlots), but only
// when every tier of the pool is saturated: the pool first squeezes the
// remaining capacity of existing connections — including expiring, heavy
// and degraded ones — and only dials a fresh connection once nothing is
// left, so transient overload does not trigger needless TLS re-dials. Uses
// double-checked locking under the scheduler lock. On first activation
// (live == 0) two connections are activated at once for better initial
// throughput, since typical web browsing generates more than 8 concurrent
// streams; falls back to 1 when maxSlots is 1.
func (s *slotScheduler) grow(highPriority bool) {
	pool := s.poolOf(highPriority)
	live := pool.liveCount.Load()
	if int(live) >= pool.maxSlots {
		// This pool is at its connection cap: new streams will cross-borrow
		// from the other pool (see pick). Make sure that pool is activated,
		// so borrowed streams land on managed slots — spread by the normal
		// tiered scheduler instead of piling onto one unmanaged slot.
		s.activateOther(pool)
		return
	}
	if live > 0 && !pool.saturatedIn(int(live)) {
		return
	}

	// Every tier of the pool is saturated — try to grow under lock.
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring the lock.
	live = pool.liveCount.Load()
	if int(live) >= pool.maxSlots {
		return
	}
	if live > 0 && !pool.saturatedIn(int(live)) {
		return
	}

	if live == 0 && pool.maxSlots >= 2 {
		pool.liveCount.Add(2)
	} else {
		pool.liveCount.Add(1)
	}
}

// activateOther activates the sibling pool when it is still unactivated
// (live == 0), doubling the first-activation semantics (+2): once a pool is
// saturated to the point of cross-borrowing, the borrowed streams deserve
// managed slots. Activation is lazy and harmless — an activated pool with
// no streams is shrunk back by the next idle sweep.
func (s *slotScheduler) activateOther(pool *slotPool) {
	other := s.otherPool(pool)
	if other.liveCount.Load() > 0 {
		return
	}
	s.mu.Lock()
	if other.liveCount.Load() == 0 {
		if other.maxSlots >= 2 {
			other.liveCount.Add(2)
		} else {
			other.liveCount.Add(1)
		}
	}
	s.mu.Unlock()
}

// shrinkIdleLocked retires every idle slot (active==0) from both pools,
// swap-removing each to the end of its pool. Caller must hold s.mu.
func (s *slotScheduler) shrinkIdleLocked() {
	for _, pool := range []*slotPool{s.priority, s.bulk} {
		for pool.removeIdleLocked() {
		}
	}
}

// removeIdleLocked swap-removes the first idle slot from the pool's live
// count. Returns false when no idle slot remains. Caller must hold s.mu.
func (p *slotPool) removeIdleLocked() bool {
	live := int(p.liveCount.Load())
	for i := 0; i < live; i++ {
		if p.slots[i].active.Load() != 0 {
			continue
		}
		p.removeAtLocked(i, live)
		return true
	}
	return false
}

// removeAtLocked swap-removes the slot at position i from the pool's live
// count. Caller must hold s.mu.
func (p *slotPool) removeAtLocked(i, live int) {
	last := live - 1
	if i != last {
		p.slots[i], p.slots[last] = p.slots[last], p.slots[i]
	}
	p.liveCount.Add(-1)
}

// remove swaps the slot out of its pool's live count (swap-remove) if it is
// still live and not hosting streams, and reports whether the removal
// happened. Streams are re-checked under the lock so a concurrent Open
// cannot be stranded. The slot's pool is found by scanning both pools for
// the pointer: each pool numbers its slots from 0 independently, so the
// stable idx alone cannot locate the pool. Called rarely (idle degraded
// slots being retired), so the linear scan over the pre-allocated arrays is
// fine.
func (s *slotScheduler) remove(sl *transportSlot) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sl.active.Load() != 0 {
		return false
	}
	for _, pool := range []*slotPool{s.priority, s.bulk} {
		live := int(pool.liveCount.Load())
		for i := 0; i < live; i++ {
			if pool.slots[i] != sl {
				continue
			}
			pool.removeAtLocked(i, live)
			return true
		}
	}
	return false
}
