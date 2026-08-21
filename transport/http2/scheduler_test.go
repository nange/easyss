package http2

import (
	"net/http"
	"testing"
)

// newTestScheduler builds a live scheduler with explicit active/heavy
// counters. Transport structs inside slots are left nil — scheduling tests
// never dial. threshold is 4, prioritySlots is 1, bulkThreshold 8.
func newTestScheduler(specs ...[2]int32) *slotScheduler {
	slots := make([]*transportSlot, len(specs))
	for i, s := range specs {
		slots[i] = &transportSlot{idx: i}
		slots[i].active.Store(s[0])
		slots[i].heavy.Store(s[1])
	}
	sch := newScheduler(len(slots), slots, 4, 1)
	sch.liveCount.Store(int32(len(slots)))
	return sch
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
		{"degraded and expiring classifies as degraded", func(s *transportSlot) {
			s.degraded.Store(true)
			s.expiring.Store(true)
		}, tierDegraded},
		{"all marks classifies as degraded", func(s *transportSlot) {
			s.degraded.Store(true)
			s.heavy.Store(1)
			s.expiring.Store(true)
		}, tierDegraded},
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
			sch := newTestScheduler([2]int32{c.actives[0], 0}, [2]int32{c.actives[1], 0})
			if got := sch.pressureLevel(0, 2, 8); got != c.want {
				t.Fatalf("pressureLevel(%v, base 8) = %d, want %d", c.actives, got, c.want)
			}
		}
	})

	t.Run("no healthy slot degrades to pool minimum", func(t *testing.T) {
		sch := newTestScheduler([2]int32{0, 0}, [2]int32{1, 0})
		sch.slots[0].expiring.Store(true)
		sch.slots[1].expiring.Store(true)
		// The active layer is empty: the pool minimum (0) is clamped to the
		// base, so the level engages at 1 instead of 0.
		if got := sch.pressureLevel(0, 2, 8); got != 1 {
			t.Fatalf("pressureLevel = %d, want 1", got)
		}

		sch2 := newTestScheduler([2]int32{16, 0}, [2]int32{16, 0})
		sch2.slots[0].degraded.Store(true)
		sch2.slots[1].degraded.Store(true)
		if got := sch2.pressureLevel(0, 2, 8); got != 2 {
			t.Fatalf("pressureLevel = %d, want 2", got)
		}
	})

	t.Run("priority base 4", func(t *testing.T) {
		sch := newTestScheduler([2]int32{4, 0}, [2]int32{4, 0})
		if got := sch.pressureLevel(0, 2, 4); got != 1 {
			t.Fatalf("pressureLevel(4, base 4) = %d, want 1", got)
		}
		sch2 := newTestScheduler([2]int32{8, 0}, [2]int32{8, 0})
		if got := sch2.pressureLevel(0, 2, 4); got != 2 {
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
		{tierActive, 0, 8, 8},     // level 0: active holds up to the base
		{tierActive, 1, 8, 0},     // level>=1: active is served by fallback only
		{tierExpiring, 0, 8, 0},   // lower tiers disabled at level 0
		{tierExpiring, 1, 8, 4},   // base/2
		{tierExpiring, 2, 8, 8},   // doubled
		{tierExpiring, 3, 8, 16},  // doubled again
		{tierHeavy, 1, 8, 2},      // base/4
		{tierHeavy, 2, 8, 4},      // base/2
		{tierHeavy, 3, 8, 8},      // base
		{tierDegraded, 1, 8, 2},   // same as heavy
		{tierDegraded, 2, 8, 4},   // same as heavy
		{tierExpiring, 1, 4, 2},   // priority base
		{tierHeavy, 1, 4, 1},      // priority base: effectively unusable
	}
	for _, tt := range tests {
		if got := (&slotScheduler{}).tierCap(tt.tier, tt.level, tt.base); got != tt.want {
			t.Fatalf("tierCap(tier=%v level=%d base=%d) = %d, want %d", tt.tier, tt.level, tt.base, got, tt.want)
		}
	}
}

func TestTieredSelectLevel0(t *testing.T) {
	t.Run("prefers least-active healthy slot", func(t *testing.T) {
		sch := newTestScheduler([2]int32{3, 0}, [2]int32{8, 0})
		slot, saturated := sch.tieredSelect(0, 2, 8)
		if saturated || slot != sch.slots[0] {
			t.Fatalf("got slot active=%d saturated=%v, want slot 0 (active=3)", slot.active.Load(), saturated)
		}
	})

	t.Run("does not engage lower tiers while active has capacity", func(t *testing.T) {
		// An idle expiring slot must NOT be chosen while a healthy slot is
		// below the base: healthy connections are preferred.
		sch := newTestScheduler([2]int32{0, 0}, [2]int32{3, 0})
		sch.slots[0].expiring.Store(true)
		slot, saturated := sch.tieredSelect(0, 2, 8)
		if saturated || slot != sch.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want healthy slot 1", slot.idx, saturated)
		}
	})
}

func TestTieredSelectLevel1(t *testing.T) {
	t.Run("spills onto expiring below base/2", func(t *testing.T) {
		sch := newTestScheduler([2]int32{8, 0}, [2]int32{2, 0}, [2]int32{1, 0})
		sch.slots[1].expiring.Store(true)
		sch.slots[2].heavy.Store(1)
		slot, saturated := sch.tieredSelect(0, 3, 8)
		if saturated || slot != sch.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want expiring slot 1 (active=2 < 4)", slot.idx, saturated)
		}
	})

	t.Run("expiring full spills onto heavy below base/4", func(t *testing.T) {
		sch := newTestScheduler([2]int32{8, 0}, [2]int32{4, 0}, [2]int32{1, 0})
		sch.slots[1].expiring.Store(true)
		sch.slots[2].heavy.Store(1)
		slot, saturated := sch.tieredSelect(0, 3, 8)
		if saturated || slot != sch.slots[2] {
			t.Fatalf("got slot %d saturated=%v, want heavy slot 2 (active=1 < 2)", slot.idx, saturated)
		}
	})

	t.Run("heavy full spills onto degraded below base/4", func(t *testing.T) {
		sch := newTestScheduler([2]int32{8, 0}, [2]int32{4, 0}, [2]int32{2, 0}, [2]int32{1, 0})
		sch.slots[1].expiring.Store(true)
		sch.slots[2].heavy.Store(1)
		sch.slots[3].degraded.Store(true)
		slot, saturated := sch.tieredSelect(0, 4, 8)
		if saturated || slot != sch.slots[3] {
			t.Fatalf("got slot %d saturated=%v, want degraded slot 3 (active=1 < 2)", slot.idx, saturated)
		}
	})

	t.Run("all tiers full falls back to healthy least-active", func(t *testing.T) {
		sch := newTestScheduler([2]int32{8, 0}, [2]int32{4, 0}, [2]int32{2, 0}, [2]int32{2, 0})
		sch.slots[1].expiring.Store(true)
		sch.slots[2].heavy.Store(1)
		sch.slots[3].degraded.Store(true)
		slot, saturated := sch.tieredSelect(0, 4, 8)
		if !saturated || slot != sch.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want fallback to healthy slot 0 with saturated=true", slot.idx, saturated)
		}
	})
}

func TestTieredSelectLevel2CapsDouble(t *testing.T) {
	t.Run("expiring capacity doubles to base", func(t *testing.T) {
		sch := newTestScheduler([2]int32{16, 0}, [2]int32{7, 0})
		sch.slots[1].expiring.Store(true)
		slot, saturated := sch.tieredSelect(0, 2, 8)
		if saturated || slot != sch.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want expiring slot 1 (active=7 < 8)", slot.idx, saturated)
		}
	})

	t.Run("heavy capacity doubles to base/2", func(t *testing.T) {
		sch := newTestScheduler([2]int32{16, 0}, [2]int32{8, 0}, [2]int32{3, 0})
		sch.slots[1].expiring.Store(true)
		sch.slots[2].heavy.Store(1)
		slot, saturated := sch.tieredSelect(0, 3, 8)
		if saturated || slot != sch.slots[2] {
			t.Fatalf("got slot %d saturated=%v, want heavy slot 2 (active=3 < 4)", slot.idx, saturated)
		}
	})
}

func TestTieredSelectPrefersLessNegative(t *testing.T) {
	t.Run("among heavy slots prefers heavy-only over heavy+expiring", func(t *testing.T) {
		sch := newTestScheduler([2]int32{8, 0}, [2]int32{1, 1}, [2]int32{1, 1})
		sch.slots[2].expiring.Store(true)
		slot, saturated := sch.tieredSelect(0, 3, 8)
		if saturated || slot != sch.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want heavy-only slot 1", slot.idx, saturated)
		}
	})

	t.Run("among degraded slots prefers degraded-only over degraded+heavy", func(t *testing.T) {
		sch := newTestScheduler([2]int32{8, 0}, [2]int32{1, 0}, [2]int32{1, 1})
		sch.slots[1].degraded.Store(true)
		sch.slots[2].degraded.Store(true)
		slot, saturated := sch.tieredSelect(0, 3, 8)
		if saturated || slot != sch.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want degraded-only slot 1", slot.idx, saturated)
		}
	})
}

func TestTieredSelectNoHealthyEngagesLowerTiers(t *testing.T) {
	t.Run("all expiring picks least-active below base/2", func(t *testing.T) {
		sch := newTestScheduler([2]int32{0, 0}, [2]int32{1, 0})
		sch.slots[0].expiring.Store(true)
		sch.slots[1].expiring.Store(true)
		slot, saturated := sch.tieredSelect(0, 2, 8)
		if saturated || slot != sch.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want expiring slot 0", slot.idx, saturated)
		}
	})

	t.Run("all negative tiers full falls back uncapped", func(t *testing.T) {
		sch := newTestScheduler([2]int32{4, 0}, [2]int32{5, 0})
		sch.slots[0].expiring.Store(true)
		sch.slots[1].expiring.Store(true)
		slot, saturated := sch.tieredSelect(0, 2, 8)
		if !saturated || slot != sch.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want least-active slot 0 with saturated=true", slot.idx, saturated)
		}
	})
}

func TestPriorityVsBulkBase(t *testing.T) {
	// Two healthy slots at 5 streams each: saturated for priority streams
	// (base 4), still open for bulk streams (base 8).
	sch := newTestScheduler([2]int32{5, 0}, [2]int32{5, 0})

	slot, saturated := sch.tieredSelect(0, 2, 4)
	if !saturated || slot == nil {
		t.Fatalf("priority base: expected saturated fallback, got slot=%v saturated=%v", slot, saturated)
	}

	slot, saturated = sch.tieredSelect(0, 2, 8)
	if saturated || slot != sch.slots[0] {
		t.Fatalf("bulk base: expected healthy slot 0, got slot %d saturated=%v", slot.idx, saturated)
	}
}

func TestPickPrefersOwnRangeThenWholePool(t *testing.T) {
	// prioritySlots=1: slot 0 is the priority range, slots 1-2 the bulk range.
	newPickScheduler := func() *slotScheduler {
		sch := newTestScheduler([2]int32{0, 0}, [2]int32{0, 0}, [2]int32{0, 0})
		sch.prioritySlots = 1
		return sch
	}

	t.Run("priority falls back to healthy bulk slot", func(t *testing.T) {
		sch := newPickScheduler()
		sch.slots[0].active.Store(4) // priority range saturated at base 4
		sch.slots[1].expiring.Store(true)
		sch.slots[1].active.Store(1)
		sch.slots[2].active.Store(2) // healthy bulk slot with capacity
		if got := sch.pick(true); got != sch.slots[2] {
			t.Fatalf("pick(true) = slot %d, want healthy bulk slot 2", got.idx)
		}
	})

	t.Run("priority falls back to expiring when no healthy bulk slot", func(t *testing.T) {
		sch := newPickScheduler()
		sch.slots[0].active.Store(4)
		sch.slots[1].expiring.Store(true)
		sch.slots[1].active.Store(1)
		sch.slots[2].active.Store(8)
		// Whole pool at base 4: active layer at threshold -> expiring tier.
		if got := sch.pick(true); got != sch.slots[1] {
			t.Fatalf("pick(true) = slot %d, want expiring slot 1", got.idx)
		}
	})

	t.Run("bulk stays in bulk range while it has capacity", func(t *testing.T) {
		sch := newPickScheduler()
		sch.slots[0].active.Store(4)
		sch.slots[1].expiring.Store(true)
		sch.slots[1].active.Store(2)
		sch.slots[2].active.Store(3)
		// Bulk range healthy least-active is slot 2 (active=3 < base 8).
		if got := sch.pick(false); got != sch.slots[2] {
			t.Fatalf("pick(false) = slot %d, want bulk slot 2", got.idx)
		}
	})
}

// newGrowTestScheduler builds a scheduler with maxSlots slots where only
// `live` are live, threshold 4 and prioritySlots priority-class slots
// (bulk threshold 8).
func newGrowTestScheduler(maxSlots, prioritySlots, live int) *slotScheduler {
	slots := make([]*transportSlot, maxSlots)
	for i := range slots {
		slots[i] = &transportSlot{}
	}
	sch := newScheduler(maxSlots, slots, 4, prioritySlots)
	sch.liveCount.Store(int32(live))
	return sch
}

// TestGrowBulkOnlyWorkloadGrowsPool guards the bulk-range fallback in grow:
// while live < prioritySlots the bulk range is empty, and a pure bulk
// workload (no priority streams to drive growth) must still grow the pool
// past the initial connections instead of piling onto them forever. Growth
// fires once every tier is saturated — with no lower tiers present that
// means every healthy slot at or beyond the bulk threshold.
func TestGrowBulkOnlyWorkloadGrowsPool(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 2)

	// Slots below the bulk threshold (8): no growth yet.
	sch.slots[0].active.Store(4)
	sch.slots[1].active.Store(7)
	sch.grow(false)
	if got := sch.liveCount.Load(); got != 2 {
		t.Fatalf("liveCount = %d, want 2 while slots still have capacity", got)
	}

	// Every live slot at or above the bulk threshold: growth must fire even
	// though the bulk range [prioritySlots, live) is empty.
	sch.slots[0].active.Store(8)
	sch.slots[1].active.Store(9)
	sch.grow(false)
	if got := sch.liveCount.Load(); got != 3 {
		t.Fatalf("liveCount = %d, want 3 (bulk workload must grow the pool)", got)
	}

	// The fallback keeps working until the bulk range becomes non-empty:
	// the newly activated slot starts idle, so saturation of all live slots
	// keeps growing the pool.
	sch.slots[2].active.Store(8)
	sch.grow(false)
	if got := sch.liveCount.Load(); got != 4 {
		t.Fatalf("liveCount = %d, want 4", got)
	}
}

func TestGrowBulkUsesBulkRangeOnceLive(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 6) // slots 0-4 priority, slot 5 bulk

	// Bulk slot below threshold: no growth.
	sch.slots[5].active.Store(7)
	sch.grow(false)
	if got := sch.liveCount.Load(); got != 6 {
		t.Fatalf("liveCount = %d, want 6 while bulk slot has capacity", got)
	}

	// Bulk slot saturated, but the priority range still hosts healthy
	// capacity: bulk streams fall back onto it instead of dialing a new
	// connection — the pool squeezes existing connections first.
	sch.slots[5].active.Store(8)
	sch.grow(false)
	if got := sch.liveCount.Load(); got != 6 {
		t.Fatalf("liveCount = %d, want 6 while the priority range has capacity", got)
	}

	// Every range saturated: grow.
	sch.slots[5].active.Store(8)
	for i := 0; i < 5; i++ {
		sch.slots[i].active.Store(8)
	}
	sch.grow(false)
	if got := sch.liveCount.Load(); got != 7 {
		t.Fatalf("liveCount = %d, want 7", got)
	}
}

func TestGrowPriorityUsesPriorityRange(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 3)

	// Priority slot below threshold (4): no growth.
	sch.slots[0].active.Store(4)
	sch.slots[1].active.Store(4)
	sch.slots[2].active.Store(3)
	sch.grow(true)
	if got := sch.liveCount.Load(); got != 3 {
		t.Fatalf("liveCount = %d, want 3 while priority slot has capacity", got)
	}

	// All live priority slots at threshold: grow.
	sch.slots[2].active.Store(4)
	sch.grow(true)
	if got := sch.liveCount.Load(); got != 4 {
		t.Fatalf("liveCount = %d, want 4", got)
	}
}

func TestGrowSqueezesNegativeTiersBeforeGrowing(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 6)

	// Healthy slot saturated at 8, but an expiring slot still has capacity
	// (base/2 = 4): new streams spill there, no growth.
	sch.slots[5].active.Store(8)
	sch.slots[0].expiring.Store(true)
	sch.slots[0].active.Store(3)
	sch.grow(false)
	if got := sch.liveCount.Load(); got != 6 {
		t.Fatalf("liveCount = %d, want 6 while expiring slot has capacity", got)
	}

	// Negative tiers saturated too: grow.
	sch.slots[0].active.Store(4)
	for i := 1; i < 5; i++ {
		sch.slots[i].active.Store(8)
	}
	sch.grow(false)
	if got := sch.liveCount.Load(); got != 7 {
		t.Fatalf("liveCount = %d, want 7 when every tier is saturated", got)
	}
}

func TestGrowFirstActivation(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 0)
	sch.grow(false)
	if got := sch.liveCount.Load(); got != 2 {
		t.Fatalf("liveCount = %d, want 2 on first activation", got)
	}

	sch1 := newGrowTestScheduler(1, 1, 0)
	sch1.grow(false)
	if got := sch1.liveCount.Load(); got != 1 {
		t.Fatalf("liveCount = %d, want 1 when maxSlots == 1", got)
	}
}

func TestRemoveShrinksLiveCount(t *testing.T) {
	s0 := &transportSlot{t: &http.Transport{}}
	s0.active.Store(1)
	s1 := &transportSlot{t: &http.Transport{}}
	s1.degraded.Store(true)
	sch := newScheduler(2, []*transportSlot{s0, s1}, 4, 1)
	sch.liveCount.Store(2)

	if !sch.remove(s1) {
		t.Fatal("idle slot must be removable")
	}
	if got := sch.liveCount.Load(); got != 1 {
		t.Fatalf("liveCount = %d, want 1", got)
	}
	if sch.slots[0] != s0 {
		t.Fatal("live slot must stay at the front")
	}

	// Busy slots are never removed.
	s2 := &transportSlot{t: &http.Transport{}}
	s2.active.Store(1)
	s2.degraded.Store(true)
	sch2 := newScheduler(1, []*transportSlot{s2}, 4, 1)
	sch2.liveCount.Store(1)
	if sch2.remove(s2) {
		t.Fatal("busy slot must not be removable")
	}
	if got := sch2.liveCount.Load(); got != 1 {
		t.Fatalf("busy slot removed: liveCount = %d", got)
	}
}
