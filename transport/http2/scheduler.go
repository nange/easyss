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
//     reached the pool's pressure base, expiring slots take over, then
//     heavy slots and finally degraded slots (worst candidate, last
//     resort). Negative tiers are compared by weighted load — the active
//     stream count times the compounded weight of the slot's negative
//     marks (heavy ×4, expiring ×8, degraded ×16, see slotWeight), so 1
//     stream on a heavy slot weighs like 4 healthy ones, 1 on an expiring
//     slot like 8 and 1 on a degraded slot like 16, while a
//     heavy+expiring+degraded slot compounds to ×512. An idle slot
//     (active == 0) carrying expiring or degraded marks still weighs its
//     mark weight — never 0, see weightedActive:
//     it must not look free, or new streams would keep the tired
//     connection alive and postpone its eviction. A slot only counts as
//     full once its weighted load reaches the tier capacity, which
//     doubles whenever the active layer is pushed to the next power-of-two
//     multiple of the base — so a fully saturated pool keeps spreading
//     load instead of piling onto one connection. Slots due for eviction
//     are never selected at all: a slot both degraded and expiring is
//     classified as tierRetiring, and an idle slot carrying expiring or
//     degraded marks is draining (see draining) — new streams must not
//     keep either alive, they drain to idle and the health loop
//     rotates/retires them, replaced by fresh connections.
//
//   - Growth prefers fresh connections over squeezing negative ones: when a
//     pool's tiers are saturated it grows its own pool, and once a pool is
//     at its connection cap it grows the sibling pool instead (the sibling
//     must also be tier-saturated; otherwise pick simply borrows its
//     healthy slots). Only when both pools are at their caps and every
//     tier is saturated do streams pile onto the least-loaded slot.
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
		if pMax > 1 {
			// Degenerate split (ratio 1 or prioritySlots >= maxSlots): give
			// the bulk pool the tail slot.
			pMax = maxSlots - 1
			bMax = 1
		} else {
			// maxSlots == 1: the bulk pool stays empty (maxSlots 0) and
			// poolOf falls back to the priority pool. Forcing bMax to 1 here
			// would make bulk.slots an empty slice with maxSlots 1, and any
			// bulk stream would index slots[0] out of range.
			bMax = 0
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
//	                clustering them; once idle the slot is draining and
//	                excluded from selection so the rotation completes;
//	tierHeavy     — heavy streams monopolize the TCP window, dragging any
//	                sharing stream down with them (head-of-line blocking
//	                under loss), yet the connection itself is healthy;
//	tierDegraded  — the connection proved persistently low throughput, the
//	                worst candidate, used only as a last resort;
//	tierRetiring  — degraded AND expiring: due for rotation and confirmed
//	                slow, with no recovery value (even a fast stream cannot
//	                undo the overdue rotation). Never selected: the slot
//	                drains to idle and the health loop retires it, replaced
//	                by a fresh connection.
type slotTier int

const (
	tierActive slotTier = iota
	tierExpiring
	tierHeavy
	tierDegraded
	tierRetiring
)

// Negative-mark load weights, shared by slotWeight (multiplicative) and
// negativeScore (additive), so the severity order always stays aligned:
// degraded 16 > expiring 8 > heavy 4. An expiring connection is worse than
// a merely heavy one — it is due for rotation and should be recycled
// quickly — hence its weight sits above heavy's; degraded sits above both
// so persistently slow connections are drained and retired first. The
// weights are deliberately high: each negative mark halves the stream
// capacity of its tier (tierCap / weight), so expiring and degraded slots
// fill with a single stream and drain to rotation/retirement quickly.
const (
	weightHeavy    = 4
	weightExpiring = 8
	weightDegraded = 16
)

// slotTierOf returns the tier a slot currently belongs to. Heavy+expiring
// slots classify as heavy (the heavier mark wins), any degraded combination
// classifies as degraded — except that a slot both degraded and expiring
// classifies as tierRetiring: it is due for rotation and confirmed slow, so
// the scheduler never selects it (see leastActive) and the health loop
// retires it once idle.
func slotTierOf(s *transportSlot) slotTier {
	if s.degraded.Load() && s.expiring.Load() {
		return tierRetiring
	}
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
// the secondary ordering key within a tier and in the uncapped fallback:
// among equally loaded slots the one with fewer negative states wins.
// Scores use the shared negative-mark weights (weightDegraded >
// weightExpiring > weightHeavy), so the severity order always matches
// slotWeight's.
func negativeScore(s *transportSlot) int32 {
	var score int32
	if s.degraded.Load() {
		score += weightDegraded
	}
	if s.heavy.Load() > 0 {
		score += weightHeavy
	}
	if s.expiring.Load() {
		score += weightExpiring
	}
	return score
}

// slotWeight returns the load weight of a slot's negative marks, the
// product of the shared negative-mark weights (weightHeavy, weightExpiring,
// weightDegraded; no mark: 1). A stream on a heavy+expiring slot weighs
// weightHeavy×weightExpiring = 32× a healthy stream, one on a
// heavy+expiring+degraded slot 4×8×16 = 512× — multiple negative states
// compound, so a slot is only considered full once its weighted load
// reaches the pool's threshold. Expiring is weighted deliberately high
// (8, above heavy's 4): the slot is due for rotation, so streams should
// avoid it and let it go idle and be recycled quickly; degraded sits even
// higher (16) so a slow connection reaches capacity with a single stream
// and drains to retirement fast. The idle floor for expiring/degraded
// marks is applied by weightedActive.
func slotWeight(s *transportSlot) int32 {
	w := int32(1)
	if s.heavy.Load() > 0 {
		w *= weightHeavy
	}
	if s.expiring.Load() {
		w *= weightExpiring
	}
	if s.degraded.Load() {
		w *= weightDegraded
	}
	return w
}

// weightedActive returns the slot's weighted load: its active stream count
// scaled by the compounded weight of all its negative marks. An idle slot
// (active == 0) carrying expiring or degraded marks counts as one stream,
// so it weighs its mark weight (expiring 8, degraded 16, both 128) instead
// of 0: without the floor it would look free and new streams would pile
// onto it, keeping the tired connection alive and starving the health
// loop's rotation/retirement. Heavy needs no floor: heavy > 0 implies at
// least one active heavy stream (the mark is released exactly once per
// stream on close), so a heavy-marked slot is never idle.
func weightedActive(s *transportSlot) int32 {
	n := s.active.Load()
	if n == 0 && (s.expiring.Load() || s.degraded.Load()) {
		n = 1
	}
	return n * slotWeight(s)
}

// draining reports whether the slot is idle (active == 0) while carrying
// an expiring or degraded mark. Such a slot is due for eviction — rotation
// or retirement — and must not be revived by new streams: the scheduler
// excludes it from selection exactly like retiring slots, so it stays idle
// until the health loop closes the connection. A draining slot is still
// used as the absolute last resort when every live slot is negative.
func draining(s *transportSlot) bool {
	return s.active.Load() == 0 && (s.expiring.Load() || s.degraded.Load())
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
		// The sibling pool may be empty (degenerate maxSlots == 1 split):
		// it owns no slots, so there is nothing to borrow and tieredSelect
		// would index its empty slot array.
		if other := s.otherPool(pool); other.maxSlots > 0 {
			otherSlot, otherSat := other.tieredSelect()
			// Borrow only when the sibling's fallback is strictly less
			// loaded, compared in weighted load so negative marks are
			// priced consistently (an idle draining slot must not look
			// free to the borrow path either).
			if !otherSat || weightedActive(otherSlot) < weightedActive(slot) {
				return otherSlot
			}
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
// accepts a slot whose weighted load (active × compounded negative-mark
// weight, floored at the mark weight for idle negative slots, see
// weightedActive) stays below the tier's capacity, which scales with the
// pressure level (see pressureLevel and tierCap). Once every tier is full,
// the fallback piles onto the least-loaded slot overall (by weighted load,
// uncapped): piling there keeps load balanced instead of stacking every
// stream onto one crowded healthy connection. Slots due for eviction are
// excluded from every search and from the fallback: slots that are both
// degraded and expiring (tierRetiring) and idle slots carrying expiring or
// degraded marks (draining, see draining) — new streams must never keep
// them alive, they drain to idle and the health loop rotates/retires them.
func (p *slotPool) tieredSelectAt(live int, recordStats bool) (*transportSlot, bool) {
	if live == 0 {
		return p.slots[0], false
	}

	level := p.pressureLevel(live)

	// consider picks the least-active, least-negative slot of one tier
	// within the current capacity; it reports whether such a slot exists.
	// Capacity is compared in weighted load (active × the compounded weight
	// of the slot's negative marks, floored at the mark weight for idle
	// negative slots), so a slot with 1 stream and one heavy mark (weight
	// 4) is still open while the pool's threshold is 8 — only once every
	// candidate slot's weighted load reaches the threshold does the pool
	// grow. Draining slots (idle with expiring/degraded marks) are skipped
	// entirely: reviving them would postpone their rotation/retirement.
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
			if slotTierOf(sl) != tier || draining(sl) {
				continue
			}
			if weightedActive(sl) >= cap {
				continue
			}
			a := sl.active.Load()
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
	// level honest). Retiring slots (degraded+expiring) are excluded from
	// the fallback too, so they drain to idle and are retired.
	return p.leastActive(live, recordStats), true
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

// tierCap returns the weighted-load capacity of one tier at the given
// pressure level: a slot of that tier accepts a new stream only while its
// weighted load (active × compounded negative-mark weight) stays below the
// capacity. The actual stream cap follows by dividing through the weight.
//
//	level 0: only the active tier has capacity, cap = base;
//	level k>=1: every negative tier has cap = 2^(k-1)*base.
//
// At level 1 that means a heavy slot holds at most base/4 streams, an
// expiring one base/8, a degraded one base/16 — 1 heavy stream counts like
// 4 healthy ones, 1 expiring like 8, 1 degraded like 16. Every level-up
// doubles the negative-tier
// capacities: the model first spills onto the negative tiers, then piles
// back onto the active layer until it doubles, then the negative-tier
// capacities double and the spill resumes — cycling until streams end and
// the load naturally falls back. Extreme levels shift beyond int32 range;
// the resulting negative capacity is treated as "no capacity" by callers.
func tierCap(tier slotTier, level, base int32) int32 {
	if level == 0 {
		if tier == tierActive {
			return base
		}
		return 0
	}
	if tier == tierActive {
		// tierActive is never actively searched at level >= 1: every
		// active slot is at or beyond the current threshold by definition,
		// so none would pass the capacity check. "Piling back onto the
		// active layer" is the fallback path in tieredSelect.
		return 0
	}
	if tier == tierRetiring {
		// tierRetiring is never searched: slots that are both degraded and
		// expiring are excluded from selection entirely (see leastActive).
		return 0
	}
	return base << (level - 1)
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

// leastActive returns the slot with the fewest weighted streams among the
// first `live` slots — the final uncapped fallback of the pressure
// scheduler; among equally loaded slots the one with fewer negative marks
// wins. Slots due for eviction are excluded: retiring slots (degraded and
// expiring) and draining slots (idle with expiring or degraded marks) must
// never be kept alive by new streams — they drain to idle and the health
// loop rotates/retires them, replaced by fresh connections via grow. When
// every live slot is due for eviction, the least-loaded such slot is
// returned so pick never fails (the health loop retires them within a tick
// or two, closing the window). With no live slots the first pre-allocated
// slot is returned. recordStats gates the tier_retiring_skipped counter
// (the grow path's saturation check must not record scheduling stats).
func (p *slotPool) leastActive(live int, recordStats bool) *transportSlot {
	if live == 0 {
		return p.slots[0]
	}
	var best *transportSlot
	var minWeighted int32 = math.MaxInt32
	var minNeg int32 = math.MaxInt32
	var lastResort *transportSlot // least-loaded retiring/draining slot, absolute last resort
	var resWeighted int32 = math.MaxInt32
	var resNeg int32 = math.MaxInt32
	for i := 0; i < live; i++ {
		sl := p.slots[i]
		w := weightedActive(sl)
		neg := negativeScore(sl)
		tier := slotTierOf(sl)
		if tier == tierRetiring || draining(sl) {
			if recordStats && tier == tierRetiring {
				stats.RecordTierRetiringSkipped()
			}
			// Among equally loaded last-resort candidates a busy slot wins
			// over a draining one: the draining slot stays idle and is
			// evicted by the health loop instead of being revived.
			better := w < resWeighted ||
				(w == resWeighted && (neg < resNeg || (neg == resNeg && !draining(sl) && draining(lastResort))))
			if better {
				lastResort, resWeighted, resNeg = sl, w, neg
			}
			continue
		}
		if w > minWeighted || (w == minWeighted && neg >= minNeg) {
			continue
		}
		best, minWeighted, minNeg = sl, w, neg
	}
	if best == nil {
		return lastResort
	}
	return best
}

// grow activates one more live slot (up to maxSlots), preferring a fresh
// connection over squeezing negative ones: when the stream's own pool's
// slots reached their thresholds (tiers saturated), the pool grows itself;
// once the pool is at its connection cap, the sibling pool is grown
// instead — but only while the sibling's slots are saturated too, so one
// pool is never inflated stream by stream by the other pool's continuous
// saturation. Only when both pools are at their caps does pick fall back
// to the tiered selection and finally the least-loaded slot.
//
// Concurrency: the growth decision and the liveCount update happen inside
// one critical section (s.mu write lock) — the unlocked fast path only
// filters out the common no-growth case, and growTarget is re-evaluated
// under the lock before any slot is activated. Concurrent growers
// therefore serialize: the first one activates a slot (which drops the
// target pool below saturation), and the next one re-checks and backs off,
// so concurrent streams can never over-grow the pool. The write lock also
// excludes concurrent pick (read lock) and shrink, keeping the live slot
// range consistent. On first activation (live == 0) two connections are
// activated at once for better initial throughput, since typical web
// browsing generates more than 8 concurrent streams; falls back to 1 when
// maxSlots is 1.
func (s *slotScheduler) grow(highPriority bool) {
	pool := s.poolOf(highPriority)
	target, _ := s.growTarget(pool)
	if target == nil {
		return
	}

	// A new connection is needed — grow under lock.
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring the lock: another grower may have
	// activated the slot (or changed the tiers) while we waited.
	target, live := s.growTarget(pool)
	if target == nil {
		return
	}
	// A revived slot must not inherit the previous connection's rotation
	// state: shrink/retire swap-remove slots out of the live set without
	// clearing their marks, so a re-activated slot would otherwise show
	// stale expiring/degraded verdicts and an overdue deadline until its
	// first dial completes. Zero the connection-scoped state before the
	// slot becomes live; the actual dial resets the deadline via resetConn.
	if live == 0 && target.maxSlots >= 2 {
		target.slots[live].resetRotation()
		target.slots[live+1].resetRotation()
		target.liveCount.Add(2)
	} else {
		target.slots[live].resetRotation()
		target.liveCount.Add(1)
	}
}

// growTarget decides whether a new connection is needed and which pool it
// belongs to; it returns nil when no pool should grow. Growth is judged by
// pool-internal slot thresholds only — a pool grows only when its own
// slots reached their thresholds (tiers saturated), and a pool is never
// inflated by the other pool's streams while its own slots still have
// capacity:
//
//   - the stream's own pool is below its cap and its tiers still have
//     capacity → no growth (pick serves the stream normally);
//   - the own pool is below its cap but tier-saturated → grow the own
//     pool (the fresh idle slot drops the pool back below saturation, so
//     growth self-throttles);
//   - the own pool is at its cap and tier-saturated → grow the sibling
//     pool, but only when the sibling is also tier-saturated (or not yet
//     activated): the sibling's fresh slot then hosts the borrowed
//     streams. While the sibling still has tier capacity, streams borrow
//     its healthy slots instead and no growth happens — this throttles
//     cross-pool growth, so one pool's continuous saturation cannot inflate
//     the other pool stream by stream;
//   - the own pool is at its cap but its tiers still have capacity → no
//     growth;
//   - both pools at their caps → no growth (pick falls back to the tiered
//     selection and finally the uncapped fallback).
func (s *slotScheduler) growTarget(pool *slotPool) (*slotPool, int32) {
	live := pool.liveCount.Load()
	if int(live) < pool.maxSlots {
		if live == 0 || pool.saturatedIn(int(live)) {
			return pool, live
		}
		return nil, 0
	}
	// Own pool at its connection cap: a new connection is only needed when
	// its slots are saturated too — otherwise the sibling pool would be
	// inflated while the own pool still has tier capacity.
	if live > 0 && !pool.saturatedIn(int(live)) {
		return nil, 0
	}
	other := s.otherPool(pool)
	live = other.liveCount.Load()
	if int(live) < other.maxSlots && (live == 0 || other.saturatedIn(int(live))) {
		return other, live
	}
	return nil, 0
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
