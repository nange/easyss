package http2

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// newTestPool builds a single live pool with explicit active/heavy
// counters. Transport structs inside slots are left nil — scheduling tests
// never dial. liveCount is set to the number of specs.
func newTestPool(base int32, specs ...[2]int32) *slotPool {
	slots := make([]*transportSlot, len(specs))
	for i, s := range specs {
		slots[i] = &transportSlot{idx: i}
		slots[i].active.Store(s[0])
		slots[i].heavy.Store(s[1])
	}
	p := &slotPool{slots: slots, maxSlots: len(slots), base: base}
	p.liveCount.Store(int32(len(slots)))
	return p
}

// newTestScheduler builds a scheduler whose priority pool holds all given
// specs (live) and whose bulk pool is empty. threshold is 4, so the
// priority pool's base is 4 and the bulk pool's base is 8.
func newTestScheduler(specs ...[2]int32) *slotScheduler {
	pSlots := make([]*transportSlot, len(specs))
	for i, s := range specs {
		pSlots[i] = &transportSlot{idx: i}
		pSlots[i].active.Store(s[0])
		pSlots[i].heavy.Store(s[1])
	}
	sch := &slotScheduler{
		priority: &slotPool{
			slots:    pSlots,
			maxSlots: len(pSlots),
			base:     4,
		},
		bulk: &slotPool{
			slots:    []*transportSlot{{}},
			maxSlots: 1,
			base:     8,
		},
		threshold:     4,
		bulkThreshold: 8,
	}
	sch.priority.liveCount.Store(int32(len(pSlots)))
	return sch
}

// newTwoPoolScheduler builds a scheduler via the production constructor
// with the given per-pool specs: the first len(pSpecs) entries form the
// priority pool (base 4), the rest the bulk pool (base 8).
func newTwoPoolScheduler(pSpecs, bSpecs [][2]int32) *slotScheduler {
	all := make([]*transportSlot, 0, len(pSpecs)+len(bSpecs))
	for i, s := range pSpecs {
		sl := &transportSlot{idx: i}
		sl.active.Store(s[0])
		sl.heavy.Store(s[1])
		all = append(all, sl)
	}
	for i, s := range bSpecs {
		sl := &transportSlot{idx: len(pSpecs) + i}
		sl.active.Store(s[0])
		sl.heavy.Store(s[1])
		all = append(all, sl)
	}
	sch := newScheduler(len(all), all, 4, len(pSpecs))
	sch.priority.liveCount.Store(int32(len(pSpecs)))
	sch.bulk.liveCount.Store(int32(len(bSpecs)))
	return sch
}

// TestSchedulerSingleSlot exercises the degenerate maxSlots == 1 split: the
// bulk pool must stay empty (maxSlots 0) so poolOf falls back to the priority
// pool instead of indexing an empty slot array (regression test: a bulk
// stream used to panic with index out of range).
func TestSchedulerSingleSlot(t *testing.T) {
	slots := make([]*transportSlot, 1)
	slots[0] = newSlot(nil, time.Second, nil, time.Minute)
	sch := newScheduler(1, slots, 4, 1)

	if sch.bulk.maxSlots != 0 || len(sch.bulk.slots) != 0 {
		t.Fatalf("bulk pool must be empty for maxSlots=1, got maxSlots=%d slots=%d",
			sch.bulk.maxSlots, len(sch.bulk.slots))
	}

	for _, highPriority := range []bool{true, false} {
		sch.grow(highPriority)
		slot := sch.pick(highPriority)
		if slot == nil {
			t.Fatalf("pick(highPriority=%v) returned nil", highPriority)
		}
		slot.active.Add(1)
		slot.active.Add(-1)
	}

	// A bulk grow must never activate more slots than the priority pool owns.
	sch.grow(false)
	if got := int(sch.priority.liveCount.Load()); got != 1 {
		t.Fatalf("priority liveCount = %d, want 1", got)
	}
	if got := int(sch.bulk.liveCount.Load()); got != 0 {
		t.Fatalf("bulk liveCount = %d, want 0", got)
	}

	// Saturate the single priority slot: pick must not try to borrow from
	// the empty bulk pool (regression test: tieredSelect on an empty pool
	// panics with index out of range).
	slots[0].active.Store(4)
	for _, highPriority := range []bool{true, false} {
		slot := sch.pick(highPriority)
		if slot == nil || slot != slots[0] {
			t.Fatalf("pick(highPriority=%v) = %v, want the single priority slot", highPriority, slot)
		}
	}
}

func TestSlotTierOf(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*transportSlot)
		expected slotTier
	}{
		{"no marks is active", func(s *transportSlot) {}, tierActive},
		{"expiring", func(s *transportSlot) { s.expiring.Store(true) }, tierExpiring},
		{"heavy", func(s *transportSlot) { s.heavy.Store(1) }, tierHeavy},
		{"heavy and expiring classifies as heavy", func(s *transportSlot) {
			s.heavy.Store(1)
			s.expiring.Store(true)
		}, tierHeavy},
		{"degraded", func(s *transportSlot) { s.degraded.Store(true) }, tierDegraded},
		{"degraded and expiring is retiring", func(s *transportSlot) {
			s.degraded.Store(true)
			s.expiring.Store(true)
		}, tierRetiring},
		{"all marks is retiring", func(s *transportSlot) {
			s.degraded.Store(true)
			s.heavy.Store(1)
			s.expiring.Store(true)
		}, tierRetiring},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sl := &transportSlot{}
			tt.setup(sl)
			if got := slotTierOf(sl); got != tt.expected {
				t.Fatalf("slotTierOf = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPressureLevel(t *testing.T) {
	t.Run("bulk base 8", func(t *testing.T) {
		cases := []struct {
			actives []int32
			want    int32
		}{
			{[]int32{7, 7}, 0},   // below base
			{[]int32{8, 8}, 1},   // first threshold
			{[]int32{15, 15}, 1}, // still below 2x base
			{[]int32{16, 16}, 2}, // 2x base
			{[]int32{31, 31}, 2}, // below 4x base
			{[]int32{32, 32}, 3}, // 4x base
		}
		for _, c := range cases {
			p := newTestPool(8, [2]int32{c.actives[0], 0}, [2]int32{c.actives[1], 0})
			if got := p.pressureLevel(int(p.liveCount.Load())); got != c.want {
				t.Fatalf("pressureLevel(%v, base 8) = %d, want %d", c.actives, got, c.want)
			}
		}
	})

	t.Run("no healthy slot degrades to pool minimum", func(t *testing.T) {
		p := newTestPool(8, [2]int32{0, 0}, [2]int32{1, 0})
		p.slots[0].expiring.Store(true)
		p.slots[1].expiring.Store(true)
		// The active layer is empty: the pool minimum (0) is clamped to the
		// base, so the level engages at 1 instead of 0.
		if got := p.pressureLevel(int(p.liveCount.Load())); got != 1 {
			t.Fatalf("pressureLevel = %d, want 1", got)
		}

		p2 := newTestPool(8, [2]int32{16, 0}, [2]int32{16, 0})
		p2.slots[0].degraded.Store(true)
		p2.slots[1].degraded.Store(true)
		if got := p2.pressureLevel(int(p2.liveCount.Load())); got != 2 {
			t.Fatalf("pressureLevel = %d, want 2", got)
		}
	})

	t.Run("priority base 4", func(t *testing.T) {
		p := newTestPool(4, [2]int32{4, 0}, [2]int32{4, 0})
		if got := p.pressureLevel(int(p.liveCount.Load())); got != 1 {
			t.Fatalf("pressureLevel(4, base 4) = %d, want 1", got)
		}
		p2 := newTestPool(4, [2]int32{8, 0}, [2]int32{8, 0})
		if got := p2.pressureLevel(int(p2.liveCount.Load())); got != 2 {
			t.Fatalf("pressureLevel(8, base 4) = %d, want 2", got)
		}
	})
}

func TestTierCap(t *testing.T) {
	tests := []struct {
		tier  slotTier
		level int32
		base  int32
		want  int32
	}{
		{tierActive, 0, 8, 8},   // level 0: active holds up to the base
		{tierActive, 1, 8, 0},   // level>=1: active is served by fallback only
		{tierExpiring, 0, 8, 0}, // negative tiers disabled at level 0
		// Weighted-load capacities at level 1: a heavy slot holds at most
		// base/4 streams (weight 4), an expiring one base/8 (weight 8), a
		// degraded one base/16 (weight 16) — 1 heavy stream counts like 4
		// healthy ones, 1 degraded like 16, 1 expiring like 8.
		{tierExpiring, 1, 8, 8},
		{tierHeavy, 1, 8, 8},
		{tierDegraded, 1, 8, 8},
		{tierExpiring, 2, 8, 16}, // doubled
		{tierExpiring, 3, 8, 32}, // doubled again
		{tierExpiring, 1, 4, 4},  // priority base
	}
	for _, tt := range tests {
		if got := tierCap(tt.tier, tt.level, tt.base); got != tt.want {
			t.Fatalf("tierCap(tier=%v level=%d base=%d) = %d, want %d", tt.tier, tt.level, tt.base, got, tt.want)
		}
	}
}

func TestWeightedActive(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*transportSlot)
		active int32
		want   int32
	}{
		{"healthy weighs 1", func(s *transportSlot) {}, 4, 4},
		{"expiring weighs 8", func(s *transportSlot) { s.expiring.Store(true) }, 2, 16},
		{"heavy weighs 4", func(s *transportSlot) { s.heavy.Store(1) }, 2, 8},
		{"degraded weighs 16", func(s *transportSlot) { s.degraded.Store(true) }, 1, 16},
		{"expiring idle floors to 8", func(s *transportSlot) { s.expiring.Store(true) }, 0, 8},
		{"degraded idle floors to 16", func(s *transportSlot) { s.degraded.Store(true) }, 0, 16},
		{"expiring and degraded idle compound to 128", func(s *transportSlot) {
			s.expiring.Store(true)
			s.degraded.Store(true)
		}, 0, 128},
		{"heavy idle stays 0 (heavy implies an active stream)", func(s *transportSlot) {
			s.heavy.Store(1)
		}, 0, 0},
		{"heavy and expiring compound to 64", func(s *transportSlot) {
			s.heavy.Store(1)
			s.expiring.Store(true)
		}, 2, 64},
		{"heavy and degraded compound to 64", func(s *transportSlot) {
			s.heavy.Store(1)
			s.degraded.Store(true)
		}, 1, 64},
		{"all marks compound to 1024", func(s *transportSlot) {
			s.heavy.Store(1)
			s.expiring.Store(true)
			s.degraded.Store(true)
		}, 2, 1024}, // 2 streams × 4(heavy) × 8(expiring) × 16(degraded)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sl := &transportSlot{}
			tt.setup(sl)
			sl.active.Store(tt.active)
			if got := weightedActive(sl); got != tt.want {
				t.Fatalf("weightedActive = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestTieredSelectLevel0(t *testing.T) {
	t.Run("prefers least-active healthy slot", func(t *testing.T) {
		p := newTestPool(8, [2]int32{3, 0}, [2]int32{8, 0})
		slot, saturated := p.tieredSelect()
		if saturated || slot != p.slots[0] {
			t.Fatalf("got slot active=%d saturated=%v, want slot 0 (active=3)", slot.active.Load(), saturated)
		}
	})

	t.Run("does not engage lower tiers while active has capacity", func(t *testing.T) {
		// An idle expiring slot must NOT be chosen while a healthy slot is
		// below the base: healthy connections are preferred.
		p := newTestPool(8, [2]int32{0, 0}, [2]int32{3, 0})
		p.slots[0].expiring.Store(true)
		slot, saturated := p.tieredSelect()
		if saturated || slot != p.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want healthy slot 1", slot.idx, saturated)
		}
	})
}

func TestTieredSelectLevel1(t *testing.T) {
	t.Run("expiring slot with one stream is already full at bulk level 1", func(t *testing.T) {
		// A single expiring stream weighs 8 = the tier capacity: the
		// expiring tier accepts no new streams at level 1, so the stream
		// spills onto the heavy slot (1 stream weighs 4 < 8).
		p := newTestPool(8, [2]int32{8, 0}, [2]int32{1, 0}, [2]int32{1, 0})
		p.slots[1].expiring.Store(true)
		p.slots[2].heavy.Store(1)
		slot, saturated := p.tieredSelect()
		if saturated || slot != p.slots[2] {
			t.Fatalf("got slot %d saturated=%v, want heavy slot 2 (active=1, weighted 4 < 8)", slot.idx, saturated)
		}
	})

	t.Run("expiring full spills onto heavy below base/4", func(t *testing.T) {
		p := newTestPool(8, [2]int32{8, 0}, [2]int32{4, 0}, [2]int32{1, 0})
		p.slots[1].expiring.Store(true)
		p.slots[2].heavy.Store(1)
		slot, saturated := p.tieredSelect()
		if saturated || slot != p.slots[2] {
			t.Fatalf("got slot %d saturated=%v, want heavy slot 2 (active=1, weighted 4 < 8)", slot.idx, saturated)
		}
	})

	t.Run("heavy slots are full with two streams at bulk level 1", func(t *testing.T) {
		// A heavy slot with 2 streams weighs 8 = the tier capacity: every
		// negative tier is full, so the pool falls back to the least-loaded
		// healthy slot.
		p := newTestPool(8, [2]int32{8, 0}, [2]int32{4, 0}, [2]int32{2, 0})
		p.slots[1].expiring.Store(true)
		p.slots[2].heavy.Store(1)
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want fallback slot 0 with saturated=true", slot.idx, saturated)
		}
	})

	t.Run("degraded slot with one stream is already full at bulk level 1", func(t *testing.T) {
		p := newTestPool(8, [2]int32{8, 0}, [2]int32{4, 0}, [2]int32{4, 0}, [2]int32{1, 0})
		p.slots[1].expiring.Store(true)
		p.slots[2].heavy.Store(1)
		p.slots[3].degraded.Store(true)
		// One degraded stream weighs 16 >= the tier capacity: the degraded
		// tier is full, so the pool falls back to the least-loaded slot —
		// the healthy one (ties broken by negativeScore).
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want fallback slot 0 with saturated=true", slot.idx, saturated)
		}
	})

	t.Run("all tiers full falls back to the least-loaded slot", func(t *testing.T) {
		p := newTestPool(8, [2]int32{8, 0}, [2]int32{4, 0}, [2]int32{4, 0}, [2]int32{2, 0})
		p.slots[1].expiring.Store(true)
		p.slots[2].heavy.Store(1)
		p.slots[3].degraded.Store(true)
		// Every tier is at capacity (weighted loads 32/16/32 >= 8); the
		// fallback is the least-loaded slot by weighted load, ties broken
		// by negativeScore.
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want fallback slot 0 with saturated=true", slot.idx, saturated)
		}
	})
}

func TestTieredSelectLevel2CapsDouble(t *testing.T) {
	t.Run("expiring capacity doubles to base", func(t *testing.T) {
		p := newTestPool(8, [2]int32{16, 0}, [2]int32{1, 0})
		p.slots[1].expiring.Store(true)
		// 1 expiring stream weighs 8 < doubled capacity 16: at level 2 the
		// expiring tier hosts a single stream (level 1 was already full).
		slot, saturated := p.tieredSelect()
		if saturated || slot != p.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want expiring slot 1 (active=1, weighted 8 < 16)", slot.idx, saturated)
		}
	})

	t.Run("heavy capacity doubles to base/4", func(t *testing.T) {
		p := newTestPool(8, [2]int32{16, 0}, [2]int32{8, 0}, [2]int32{3, 0})
		p.slots[1].expiring.Store(true)
		p.slots[2].heavy.Store(1)
		slot, saturated := p.tieredSelect()
		if saturated || slot != p.slots[2] {
			t.Fatalf("got slot %d saturated=%v, want heavy slot 2 (active=3 < 4)", slot.idx, saturated)
		}
	})
}

func TestTieredSelectPrefersLessNegative(t *testing.T) {
	t.Run("among heavy slots prefers heavy-only over heavy+expiring", func(t *testing.T) {
		// Both host 1 stream; the heavy-only slot weighs 4 < 8 and is
		// open, the heavy+expiring one weighs 32 and is full.
		p := newTestPool(8, [2]int32{8, 0}, [2]int32{1, 1}, [2]int32{1, 1})
		p.slots[2].expiring.Store(true)
		slot, saturated := p.tieredSelect()
		if saturated || slot != p.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want heavy-only slot 1", slot.idx, saturated)
		}
	})

	t.Run("among degraded slots prefers degraded-only over degraded+heavy", func(t *testing.T) {
		// Level 3 (capacity 32): a single degraded stream (weighted 16) is
		// still open, while degraded+heavy (weighted 32) is full.
		p := newTestPool(8, [2]int32{32, 0}, [2]int32{1, 0}, [2]int32{1, 1})
		p.slots[1].degraded.Store(true)
		p.slots[2].degraded.Store(true)
		slot, saturated := p.tieredSelect()
		if saturated || slot != p.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want degraded-only slot 1", slot.idx, saturated)
		}
	})
}

func TestTieredSelectExcludesRetiring(t *testing.T) {
	t.Run("degraded tier prefers degraded-only over idle retiring", func(t *testing.T) {
		// Level 3 (capacity 32): the expiring/heavy tiers are full and a
		// single degraded stream (weighted 16 < 32) is still open; the idle
		// retiring slot is excluded and must not win the tier.
		p := newTestPool(8, [2]int32{32, 0}, [2]int32{4, 0}, [2]int32{8, 0}, [2]int32{0, 0}, [2]int32{1, 0})
		p.slots[1].expiring.Store(true)
		p.slots[2].heavy.Store(1)
		p.slots[3].degraded.Store(true)
		p.slots[3].expiring.Store(true) // idle retiring slot: excluded
		p.slots[4].degraded.Store(true)
		// The idle retiring slot must NOT win the degraded tier: retiring
		// slots are excluded, so the degraded-only slot hosting one stream
		// is picked.
		slot, saturated := p.tieredSelect()
		if saturated || slot != p.slots[4] {
			t.Fatalf("got slot %d saturated=%v, want degraded-only slot 4 (active=1, weighted 16 < 32)", slot.idx, saturated)
		}
	})

	t.Run("uncapped fallback excludes idle retiring", func(t *testing.T) {
		p := newTestPool(8, [2]int32{8, 0}, [2]int32{4, 0}, [2]int32{4, 0}, [2]int32{2, 0}, [2]int32{0, 0})
		p.slots[1].expiring.Store(true)
		p.slots[2].heavy.Store(1)
		p.slots[3].degraded.Store(true)
		p.slots[4].degraded.Store(true)
		p.slots[4].expiring.Store(true)
		// Every tier is at capacity; the idle retiring slot (floored
		// weight 128) would not be the globally least-loaded slot anyway,
		// but it must be passed over in favor of the least-loaded healthy
		// slot regardless.
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want fallback slot 0 with saturated=true", slot.idx, saturated)
		}
	})

	t.Run("all live slots retiring returns the least-loaded retiring slot", func(t *testing.T) {
		p := newTestPool(8, [2]int32{2, 0}, [2]int32{0, 0})
		p.slots[0].degraded.Store(true)
		p.slots[0].expiring.Store(true)
		p.slots[1].degraded.Store(true)
		p.slots[1].expiring.Store(true)
		// No alternative exists: pick must never fail, so the least-loaded
		// retiring slot is returned (the health loop retires both shortly);
		// the idle one (floored weight 128) wins over the busy one (256).
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want least-loaded retiring slot 1", slot.idx, saturated)
		}
	})

	t.Run("all live slots retiring prefers the busy slot on a tie", func(t *testing.T) {
		p := newTestPool(8, [2]int32{1, 0}, [2]int32{0, 0})
		p.slots[0].degraded.Store(true)
		p.slots[0].expiring.Store(true)
		p.slots[1].degraded.Store(true)
		p.slots[1].expiring.Store(true)
		// Both weigh 128 (the idle slot is floored at its mark weight): the
		// tie goes to the busy slot, so the idle one stays idle and is
		// retired by the health loop instead of being revived.
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want busy retiring slot 0", slot.idx, saturated)
		}
	})
}

func TestTieredSelectDraining(t *testing.T) {
	t.Run("idle expiring slot is not revived at bulk level 1", func(t *testing.T) {
		p := newTestPool(8, [2]int32{8, 0}, [2]int32{0, 0})
		p.slots[1].expiring.Store(true)
		// The healthy slot is at the base (level 1) and the expiring slot
		// is idle — draining: the tier search skips it and the fallback
		// excludes it, so the stream lands on the healthy slot and the
		// pool reports saturated (grow then dials a fresh connection
		// instead of reviving the tired one).
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want healthy slot 0 with saturated=true", slot.idx, saturated)
		}
	})

	t.Run("busy degraded slot preferred over idle degraded slot", func(t *testing.T) {
		// Level 3 (capacity 32): a single degraded stream (weighted 16) is
		// still open; the idle one is draining and skipped.
		p := newTestPool(8, [2]int32{32, 0}, [2]int32{1, 0}, [2]int32{0, 0})
		p.slots[1].degraded.Store(true)
		p.slots[2].degraded.Store(true)
		slot, saturated := p.tieredSelect()
		if saturated || slot != p.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want busy degraded slot 1", slot.idx, saturated)
		}
	})

	t.Run("uncapped fallback excludes idle negative slots", func(t *testing.T) {
		p := newTestPool(8, [2]int32{8, 0}, [2]int32{4, 0}, [2]int32{4, 0}, [2]int32{2, 0}, [2]int32{0, 0})
		p.slots[1].expiring.Store(true)
		p.slots[2].heavy.Store(1)
		p.slots[3].degraded.Store(true)
		p.slots[4].expiring.Store(true)
		// Every tier is at capacity; the idle expiring slot (floored
		// weight 8) would be the globally least-loaded slot, but it is
		// draining and must be passed over in favor of the least-loaded
		// healthy slot.
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want fallback slot 0 with saturated=true", slot.idx, saturated)
		}
	})

	t.Run("all live slots draining returns the least-loaded draining slot", func(t *testing.T) {
		p := newTestPool(8, [2]int32{0, 0}, [2]int32{0, 0})
		p.slots[0].expiring.Store(true)
		p.slots[1].degraded.Store(true)
		// No alternative exists: pick must never fail, so the least-loaded
		// draining slot is returned (the health loop rotates/retires them
		// shortly); the idle expiring slot (weight 8) wins over the idle
		// degraded one (weight 16).
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want least-loaded draining slot 0", slot.idx, saturated)
		}
	})
}

func TestGrowReplacesDrainingSlot(t *testing.T) {
	// A healthy slot at the base plus an idle expiring slot: the draining
	// slot is excluded from selection, so the pool counts as saturated and
	// a fresh connection is grown instead of reviving the tired one.
	sch := newGrowTestScheduler(10, 5, 0, 2)
	sch.bulk.slots[0].active.Store(8)
	sch.bulk.slots[1].expiring.Store(true)
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 3 {
		t.Fatalf("bulk liveCount = %d, want 3 (fresh connection replaces the draining slot)", got)
	}
}

func TestPickDoesNotBorrowDrainingSlot(t *testing.T) {
	sch := newTwoPoolScheduler(
		[][2]int32{{4, 0}}, // priority pool saturated at base 4
		[][2]int32{{8, 0}, {0, 0}},
	)
	sch.bulk.slots[1].expiring.Store(true)
	// The bulk pool's only non-draining slot is at the base; the idle
	// expiring slot is draining and must not be borrowed — the stream
	// stays on the own pool's fallback.
	if got := sch.pick(true); got != sch.priority.slots[0] {
		t.Fatalf("pick(true) = slot %d, want own pool fallback slot 0", got.idx)
	}
}

func TestTieredSelectNoHealthyEngagesLowerTiers(t *testing.T) {
	t.Run("all expiring picks the busy slot over the idle draining one", func(t *testing.T) {
		p := newTestPool(8, [2]int32{0, 0}, [2]int32{1, 0})
		p.slots[0].expiring.Store(true)
		p.slots[1].expiring.Store(true)
		// Slot 0 is idle and expiring — draining: new streams must not
		// revive it (reviving would postpone its rotation). The busy
		// expiring slot 1 is full too (1 stream weighs 8 = the tier
		// capacity), so the fallback still lands on it — the only
		// non-draining candidate — and the pool reports saturated, so grow
		// dials a fresh connection instead of reviving either tired slot.
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want busy expiring slot 1 with saturated=true", slot.idx, saturated)
		}
	})

	t.Run("all negative tiers full falls back uncapped", func(t *testing.T) {
		p := newTestPool(8, [2]int32{4, 0}, [2]int32{5, 0})
		p.slots[0].expiring.Store(true)
		p.slots[1].expiring.Store(true)
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want least-active slot 0 with saturated=true", slot.idx, saturated)
		}
	})
}

func TestPriorityVsBulkBase(t *testing.T) {
	// Two healthy slots at 5 streams each: saturated for priority streams
	// (base 4), still open for bulk streams (base 8).
	p4 := newTestPool(4, [2]int32{5, 0}, [2]int32{5, 0})
	if slot, saturated := p4.tieredSelect(); !saturated || slot == nil {
		t.Fatalf("priority base: expected saturated fallback, got slot=%v saturated=%v", slot, saturated)
	}
	p8 := newTestPool(8, [2]int32{5, 0}, [2]int32{5, 0})
	if slot, saturated := p8.tieredSelect(); saturated || slot != p8.slots[0] {
		t.Fatalf("bulk base: expected healthy slot 0, got slot %d saturated=%v", slot.idx, saturated)
	}
}

func TestPickBorrowsOtherPoolWhenSaturated(t *testing.T) {
	t.Run("priority borrows healthy bulk slot", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{4, 0}}, // priority pool saturated at base 4
			[][2]int32{{1, 0}, {2, 0}},
		)
		sch.bulk.slots[0].expiring.Store(true)
		// Bulk pool healthy least-active is slot with active=2.
		if got := sch.pick(true); got != sch.bulk.slots[1] {
			t.Fatalf("pick(true) = slot %d, want borrowed bulk slot (active=2)", got.idx)
		}
	})

	t.Run("priority borrows expiring bulk slot when bulk has no healthy capacity", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{4, 0}},
			[][2]int32{{16, 0}, {1, 0}},
		)
		sch.bulk.slots[1].expiring.Store(true)
		// Bulk pool: healthy layer at 16 (level 2) -> expiring tier
		// (active=1, weighted 8 < 16).
		if got := sch.pick(true); got != sch.bulk.slots[1] {
			t.Fatalf("pick(true) = slot %d, want borrowed expiring bulk slot 1", got.idx)
		}
	})

	t.Run("bulk borrows healthy priority slot", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{1, 0}},
			[][2]int32{{8, 0}}, // bulk pool saturated at base 8
		)
		// Priority pool has healthy capacity (active=1 < 4).
		if got := sch.pick(false); got != sch.priority.slots[0] {
			t.Fatalf("pick(false) = slot %d, want borrowed priority slot 0", got.idx)
		}
	})

	t.Run("both pools saturated returns own pool fallback", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{4, 0}},
			[][2]int32{{8, 0}, {8, 0}},
		)
		if got := sch.pick(true); got != sch.priority.slots[0] {
			t.Fatalf("pick(true) = slot %d, want own pool fallback slot 0", got.idx)
		}
	})

	t.Run("borrows other pool fallback when it is less loaded", func(t *testing.T) {
		// Priority pool saturated (heavy slot at 8 streams, fallback
		// weighted 32); bulk pool saturated too (heavy slots at 2/8
		// streams weigh 8/32 >= base 8), but its fallback slot hosts 2
		// streams (weighted 8) vs our 32 — the new stream must go there
		// instead of piling onto the 8-stream slot.
		sch := newTwoPoolScheduler(
			[][2]int32{{8, 1}},
			[][2]int32{{2, 1}, {8, 1}},
		)
		sch.bulk.slots[1].expiring.Store(true)
		if got := sch.pick(true); got != sch.bulk.slots[0] {
			t.Fatalf("pick(true) = slot %d, want less-loaded bulk slot 0 (active=2)", got.idx)
		}
	})

	t.Run("keeps own fallback when the other pool is not less loaded", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{2, 0}},
			[][2]int32{{4, 1}, {8, 1}},
		)
		sch.priority.slots[0].heavy.Store(1)
		// Priority pool: heavy slot at 2 streams weighs 8 = 2× its base 4,
		// so it is saturated and falls back to slot 0 (weighted 8). Bulk
		// pool: heavy slots at 4/8 streams (weighted 16/32) are saturated
		// too, its fallback sits at 4 streams — not less loaded, so the
		// stream stays in its own pool.
		if got := sch.pick(true); got != sch.priority.slots[0] {
			t.Fatalf("pick(true) = slot %d, want own pool fallback slot 0", got.idx)
		}
	})
}

func TestPickExcludesRetiringInBorrow(t *testing.T) {
	t.Run("borrows healthy bulk slot over idle retiring bulk slot", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{4, 0}}, // priority pool saturated at base 4
			[][2]int32{{0, 0}, {1, 0}},
		)
		sch.bulk.slots[0].degraded.Store(true)
		sch.bulk.slots[0].expiring.Store(true)
		// The idle retiring bulk slot must not win the borrow: the healthy
		// bulk slot (active=1) is borrowed instead.
		if got := sch.pick(true); got != sch.bulk.slots[1] {
			t.Fatalf("pick(true) = slot %d, want borrowed healthy bulk slot 1", got.idx)
		}
	})

	t.Run("all bulk slots retiring keeps the own pool fallback", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{4, 0}},
			[][2]int32{{1, 0}, {0, 0}},
		)
		sch.bulk.slots[0].degraded.Store(true)
		sch.bulk.slots[0].expiring.Store(true)
		sch.bulk.slots[1].degraded.Store(true)
		sch.bulk.slots[1].expiring.Store(true)
		// The bulk pool is entirely retiring: its fallback (the busy slot,
		// weighted 128 — the idle one is floored to the same 128) outweighs
		// the own pool's fallback (weighted 4), so the stream stays in the
		// own pool instead of reviving a doomed connection.
		if got := sch.pick(true); got != sch.priority.slots[0] {
			t.Fatalf("pick(true) = slot %d, want own pool fallback slot 0", got.idx)
		}
	})
}

// newGrowTestScheduler builds a scheduler via the production constructor
// with maxSlots total slots, prioritySlots priority-class slots, threshold 4
// and the given live counts per pool (all remaining slots live as bulk).
func newGrowTestScheduler(maxSlots, prioritySlots, pLive, bLive int) *slotScheduler {
	slots := make([]*transportSlot, maxSlots)
	for i := range slots {
		slots[i] = &transportSlot{idx: i}
	}
	sch := newScheduler(maxSlots, slots, 4, prioritySlots)
	sch.priority.liveCount.Store(int32(pLive))
	sch.bulk.liveCount.Store(int32(bLive))
	return sch
}

func TestGrowBulkPoolIndependentOfPriority(t *testing.T) {
	// priority pool has 5 slots (0-4), bulk pool 5 (5-9). Only one bulk
	// slot is live.
	sch := newGrowTestScheduler(10, 5, 0, 1)

	// Bulk slot below the bulk threshold (8): no growth.
	sch.bulk.slots[0].active.Store(7)
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 1 {
		t.Fatalf("bulk liveCount = %d, want 1 while bulk slot has capacity", got)
	}

	// Bulk slot saturated: grow — regardless of the (empty) priority pool,
	// each pool grows on its own demand.
	sch.bulk.slots[0].active.Store(8)
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 2 {
		t.Fatalf("bulk liveCount = %d, want 2", got)
	}
	if got := sch.priority.liveCount.Load(); got != 0 {
		t.Fatalf("priority liveCount = %d, want 0 (pools grow independently)", got)
	}
}

func TestGrowPriorityPool(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 3, 0)

	// Priority slot below threshold (4): no growth.
	sch.priority.slots[0].active.Store(4)
	sch.priority.slots[1].active.Store(4)
	sch.priority.slots[2].active.Store(3)
	sch.grow(true)
	if got := sch.priority.liveCount.Load(); got != 3 {
		t.Fatalf("priority liveCount = %d, want 3 while priority slot has capacity", got)
	}

	// All live priority slots at threshold: grow.
	sch.priority.slots[2].active.Store(4)
	sch.grow(true)
	if got := sch.priority.liveCount.Load(); got != 4 {
		t.Fatalf("priority liveCount = %d, want 4", got)
	}
}

func TestNoGrowthWhileNegativeTiersHaveCapacity(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 5, 2)

	// At level 1 an expiring slot is full with a single stream, so the
	// capacity check runs at level 2 (healthy slot at 16): the expiring
	// slot still has capacity (1 stream weighs 8 < 16), the stream is
	// served there, no growth.
	sch.bulk.slots[0].active.Store(16)
	sch.bulk.slots[1].expiring.Store(true)
	sch.bulk.slots[1].active.Store(1)
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 2 {
		t.Fatalf("bulk liveCount = %d, want 2 while expiring slot has capacity", got)
	}

	// Negative tiers saturated too (2 expiring streams weigh 16 >= 16): grow.
	sch.bulk.slots[1].active.Store(2)
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 3 {
		t.Fatalf("bulk liveCount = %d, want 3 when every tier is saturated", got)
	}
}

func TestGrowWhenOnlyRetiringCapacityRemains(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 0, 2)

	// One healthy slot saturated at 8; the other slot is retiring
	// (degraded+expiring) and idle. Its weighted load is 0, but retiring
	// slots are excluded from selection, so the pool counts as saturated
	// and a fresh connection is grown to replace the doomed slot.
	sch.bulk.slots[0].active.Store(8)
	sch.bulk.slots[1].degraded.Store(true)
	sch.bulk.slots[1].expiring.Store(true)
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 3 {
		t.Fatalf("bulk liveCount = %d, want 3 when the only remaining capacity is a retiring slot", got)
	}
}

func TestGrowGrowsSiblingPoolWhenOwnPoolFull(t *testing.T) {
	t.Run("priority pool full grows unactivated bulk pool", func(t *testing.T) {
		// priority pool (5 slots) at its cap with every slot at the
		// threshold, bulk pool never used: new priority streams need fresh
		// connections, so the sibling pool is grown (with first-activation
		// +2 semantics).
		sch := newGrowTestScheduler(10, 5, 5, 0)
		for i := 0; i < 5; i++ {
			sch.priority.slots[i].active.Store(4)
		}
		sch.grow(true)
		if got := sch.bulk.liveCount.Load(); got != 2 {
			t.Fatalf("bulk liveCount = %d, want 2 (sibling grown for borrowing)", got)
		}
		if got := sch.priority.liveCount.Load(); got != 5 {
			t.Fatalf("priority liveCount = %d, want 5 (unchanged)", got)
		}
	})

	t.Run("grows sibling when both pools are saturated", func(t *testing.T) {
		// Own pool at its cap with every slot at the threshold (4), and
		// the sibling pool's slots saturated too (8 each): a new
		// connection is genuinely needed, so the sibling grows.
		sch := newGrowTestScheduler(10, 5, 5, 2)
		for i := 0; i < 5; i++ {
			sch.priority.slots[i].active.Store(4)
		}
		sch.bulk.slots[0].active.Store(8)
		sch.bulk.slots[1].active.Store(8)
		sch.grow(true)
		if got := sch.bulk.liveCount.Load(); got != 3 {
			t.Fatalf("bulk liveCount = %d, want 3 (sibling grown while both pools saturated)", got)
		}
	})

	t.Run("does not grow sibling while own pool still has tier capacity", func(t *testing.T) {
		// The reported snapshot: the priority pool is at its connection
		// cap but its slots hold 3-4 streams (healthy min below the
		// threshold 4) — the bulk pool must NOT be inflated while the
		// priority slots can still serve streams.
		sch := newGrowTestScheduler(10, 5, 5, 2)
		sch.priority.slots[0].active.Store(3)
		sch.priority.slots[1].active.Store(3)
		sch.priority.slots[2].active.Store(3)
		sch.priority.slots[3].active.Store(4)
		sch.priority.slots[3].heavy.Store(1)
		sch.priority.slots[4].active.Store(4)
		sch.grow(true)
		if got := sch.bulk.liveCount.Load(); got != 2 {
			t.Fatalf("bulk liveCount = %d, want 2 (own pool still has tier capacity)", got)
		}
	})

	t.Run("does not grow sibling while sibling has tier capacity", func(t *testing.T) {
		// Priority pool saturated, bulk pool holds two heavy slots at 1
		// and 8 streams: the 1-stream slot weighs 4 < base 8, so the bulk
		// pool still has tier capacity — streams borrow it instead of
		// growing it. Cross-pool growth is throttled by the sibling's own
		// slot thresholds.
		sch := newGrowTestScheduler(10, 5, 5, 2)
		for i := 0; i < 5; i++ {
			sch.priority.slots[i].active.Store(4)
		}
		sch.bulk.slots[0].active.Store(1)
		sch.bulk.slots[0].heavy.Store(1)
		sch.bulk.slots[1].active.Store(8)
		sch.bulk.slots[1].heavy.Store(1)
		sch.grow(true)
		if got := sch.bulk.liveCount.Load(); got != 2 {
			t.Fatalf("bulk liveCount = %d, want 2 (sibling still has tier capacity)", got)
		}
	})

	t.Run("does not inflate a healthy sibling stream by stream", func(t *testing.T) {
		// The reported snapshot: priority pool saturated (healthy slots at
		// 4, heavy slots at 4/4/3 — 3 heavy streams weigh 12 >= base 4),
		// bulk pool holds seven 1-stream healthy slots: far from its
		// threshold 8, so growth must not happen.
		sch := newGrowTestScheduler(14, 5, 5, 9)
		sch.priority.slots[0].active.Store(4)
		sch.priority.slots[1].active.Store(4)
		sch.priority.slots[2].active.Store(4)
		sch.priority.slots[2].heavy.Store(1)
		sch.priority.slots[3].active.Store(4)
		sch.priority.slots[3].heavy.Store(1)
		sch.priority.slots[4].active.Store(3)
		sch.priority.slots[4].heavy.Store(1)
		for i := 0; i < 7; i++ {
			sch.bulk.slots[i].active.Store(1)
		}
		sch.grow(true)
		if got := sch.bulk.liveCount.Load(); got != 9 {
			t.Fatalf("bulk liveCount = %d, want 9 (sibling must not be inflated)", got)
		}
	})

	t.Run("bulk pool full grows unactivated priority pool", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 0, 5)
		for i := 0; i < 5; i++ {
			sch.bulk.slots[i].active.Store(8)
		}
		sch.grow(false)
		if got := sch.priority.liveCount.Load(); got != 2 {
			t.Fatalf("priority liveCount = %d, want 2 (sibling grown for borrowing)", got)
		}
		if got := sch.bulk.liveCount.Load(); got != 5 {
			t.Fatalf("bulk liveCount = %d, want 5 (unchanged)", got)
		}
	})

	t.Run("both pools full never grows", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 5, 5)
		for i := 0; i < 5; i++ {
			sch.priority.slots[i].active.Store(4)
			sch.bulk.slots[i].active.Store(8)
		}
		sch.grow(true)
		if got := sch.priority.liveCount.Load() + sch.bulk.liveCount.Load(); got != 10 {
			t.Fatalf("total liveCount = %d, want 10 (both pools at their caps)", got)
		}
	})
}

// TestGrowConcurrent stresses grow's double-checked locking: concurrent
// growers must serialize on the write lock and re-evaluate under it, so a
// burst of streams can never over-grow a pool.
func TestGrowConcurrent(t *testing.T) {
	t.Run("concurrent growers activate the sibling once", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 5, 0)
		for i := 0; i < 5; i++ {
			sch.priority.slots[i].active.Store(4)
		}
		const n = 64
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				sch.grow(true)
			}()
		}
		wg.Wait()
		if got := sch.bulk.liveCount.Load(); got != 2 {
			t.Fatalf("bulk liveCount = %d, want 2 (single first activation under concurrency)", got)
		}
	})

	t.Run("concurrent growers add at most one slot", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 5, 2)
		for i := 0; i < 5; i++ {
			sch.priority.slots[i].active.Store(4)
		}
		sch.bulk.slots[0].active.Store(8)
		sch.bulk.slots[1].active.Store(8)
		const n = 64
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				sch.grow(true)
			}()
		}
		wg.Wait()
		if got := sch.bulk.liveCount.Load(); got != 3 {
			t.Fatalf("bulk liveCount = %d, want 3 (at most one slot added under concurrency)", got)
		}
	})
}

func TestGrowFirstActivationPerPool(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 0, 0)

	// The first priority stream activates 2 priority connections...
	sch.grow(true)
	if got := sch.priority.liveCount.Load(); got != 2 {
		t.Fatalf("priority liveCount = %d, want 2 on first activation", got)
	}
	if got := sch.bulk.liveCount.Load(); got != 0 {
		t.Fatalf("bulk liveCount = %d, want 0 (lazy, not yet used)", got)
	}

	// ...and the first bulk stream (e.g. a DNS query) activates 2 bulk
	// connections of its own.
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 2 {
		t.Fatalf("bulk liveCount = %d, want 2 on first activation", got)
	}
}

func TestRemoveShrinksLiveCountAndLocatesPool(t *testing.T) {
	s0 := &transportSlot{t: &http.Transport{}}
	s0.active.Store(1)
	s1 := &transportSlot{t: &http.Transport{}}
	s1.degraded.Store(true)
	sch := newScheduler(2, []*transportSlot{s0, s1}, 4, 1) // priority 1, bulk 1
	sch.priority.liveCount.Store(1)
	sch.bulk.liveCount.Store(1)

	// s1 lives in the bulk pool (the constructor assigns per-pool indices
	// and remove locates the pool by scanning both pools).
	if !sch.remove(s1) {
		t.Fatal("idle bulk slot must be removable")
	}
	if got := sch.bulk.liveCount.Load(); got != 0 {
		t.Fatalf("bulk liveCount = %d, want 0", got)
	}
	if got := sch.priority.liveCount.Load(); got != 1 {
		t.Fatalf("priority liveCount = %d, want 1 (untouched)", got)
	}

	// Busy slots are never removed.
	if sch.remove(s0) {
		t.Fatal("busy slot must not be removable")
	}
	if got := sch.priority.liveCount.Load(); got != 1 {
		t.Fatalf("priority liveCount = %d, want 1", got)
	}
}
