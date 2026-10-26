package http2

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
	}
	sch.priority.liveCount.Store(int32(len(pSlots)))
	return sch
}

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

// 防回归：maxSlots==1 时 bulk 池必须为空，否则 poolOf 会回退到 priority
// 而不是索引空槽位数组。
func TestSchedulerSingleSlot(t *testing.T) {
	slots := make([]*transportSlot, 1)
	slots[0] = slotWithPool(&http.Transport{})
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

	sch.grow(false)
	if got := int(sch.priority.liveCount.Load()); got != 1 {
		t.Fatalf("priority liveCount = %d, want 1", got)
	}
	if got := int(sch.bulk.liveCount.Load()); got != 0 {
		t.Fatalf("bulk liveCount = %d, want 0", got)
	}

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
			{[]int32{7, 7}, 0},
			{[]int32{8, 8}, 1},
			{[]int32{15, 15}, 1},
			{[]int32{16, 16}, 2},
			{[]int32{31, 31}, 2},
			{[]int32{32, 32}, 3},
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
		{tierActive, 0, 8, 8},
		{tierActive, 1, 8, 0},
		{tierExpiring, 0, 8, 0},
		// 加权负载：heavy 流权重 4、expiring 8、degraded 16，层级容量按 base 折算。
		{tierExpiring, 1, 8, 8},
		{tierHeavy, 1, 8, 8},
		{tierDegraded, 1, 8, 8},
		{tierExpiring, 2, 8, 16},
		{tierExpiring, 3, 8, 32},
		{tierExpiring, 1, 4, 4},
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
		}, 2, 1024}, // 2 条流 × 4(heavy) × 8(expiring) × 16(degraded)
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
		// 健康槽位仍有容量时不得启用下层（负向）槽位。
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
		// 负向层级全满时回退到负载最少的健康槽位，平局按 negativeScore 打破。
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
		p := newTestPool(8, [2]int32{8, 0}, [2]int32{1, 1}, [2]int32{1, 1})
		p.slots[2].expiring.Store(true)
		slot, saturated := p.tieredSelect()
		if saturated || slot != p.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want heavy-only slot 1", slot.idx, saturated)
		}
	})

	t.Run("among degraded slots prefers degraded-only over degraded+heavy", func(t *testing.T) {
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
		p := newTestPool(8, [2]int32{32, 0}, [2]int32{4, 0}, [2]int32{8, 0}, [2]int32{0, 0}, [2]int32{1, 0})
		p.slots[1].expiring.Store(true)
		p.slots[2].heavy.Store(1)
		p.slots[3].degraded.Store(true)
		p.slots[3].expiring.Store(true)
		p.slots[4].degraded.Store(true)
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
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want fallback slot 0 with saturated=true", slot.idx, saturated)
		}
	})

	t.Run("all live slots retiring returns the least-loaded retiring slot", func(t *testing.T) {
		// pick 绝不能失败：全都 retiring 时返回负载最少的那个，健康循环随后退役它们。
		p := newTestPool(8, [2]int32{2, 0}, [2]int32{0, 0})
		p.slots[0].degraded.Store(true)
		p.slots[0].expiring.Store(true)
		p.slots[1].degraded.Store(true)
		p.slots[1].expiring.Store(true)
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
		// 平局归于忙碌槽位：空闲槽位留给健康循环退役，而不是在这里被重新激活。
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
		// 空闲的 expiring 槽位处于 draining：层级搜索与 fallback 都跳过它，池因此报告饱和。
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want healthy slot 0 with saturated=true", slot.idx, saturated)
		}
	})

	t.Run("busy degraded slot preferred over idle degraded slot", func(t *testing.T) {
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
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want fallback slot 0 with saturated=true", slot.idx, saturated)
		}
	})

	t.Run("all live slots draining returns the least-loaded draining slot", func(t *testing.T) {
		// pick 绝不能失败：全都 draining 时返回负载最少的那个。
		p := newTestPool(8, [2]int32{0, 0}, [2]int32{0, 0})
		p.slots[0].expiring.Store(true)
		p.slots[1].degraded.Store(true)
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want least-loaded draining slot 0", slot.idx, saturated)
		}
	})
}

func TestGrowReplacesDrainingSlot(t *testing.T) {
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
		[][2]int32{{4, 0}}, // priority 池在 base 4 处饱和
		[][2]int32{{8, 0}, {0, 0}},
	)
	sch.bulk.slots[1].expiring.Store(true)
	if got := sch.pick(true); got != sch.priority.slots[0] {
		t.Fatalf("pick(true) = slot %d, want own pool fallback slot 0", got.idx)
	}
}

func TestTieredSelectNoHealthyEngagesLowerTiers(t *testing.T) {
	t.Run("all expiring picks the busy slot over the idle draining one", func(t *testing.T) {
		p := newTestPool(8, [2]int32{0, 0}, [2]int32{1, 0})
		p.slots[0].expiring.Store(true)
		p.slots[1].expiring.Store(true)
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
			[][2]int32{{4, 0}},
			[][2]int32{{1, 0}, {2, 0}},
		)
		sch.bulk.slots[0].expiring.Store(true)
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
		if got := sch.pick(true); got != sch.bulk.slots[1] {
			t.Fatalf("pick(true) = slot %d, want borrowed expiring bulk slot 1", got.idx)
		}
	})

	t.Run("bulk borrows healthy priority slot", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{1, 0}},
			[][2]int32{{8, 0}},
		)
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
		if got := sch.pick(true); got != sch.priority.slots[0] {
			t.Fatalf("pick(true) = slot %d, want own pool fallback slot 0", got.idx)
		}
	})
}

func TestPickExcludesRetiringInBorrow(t *testing.T) {
	t.Run("borrows healthy bulk slot over idle retiring bulk slot", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{4, 0}},
			[][2]int32{{0, 0}, {1, 0}},
		)
		sch.bulk.slots[0].degraded.Store(true)
		sch.bulk.slots[0].expiring.Store(true)
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
		if got := sch.pick(true); got != sch.priority.slots[0] {
			t.Fatalf("pick(true) = slot %d, want own pool fallback slot 0", got.idx)
		}
	})
}

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
	sch := newGrowTestScheduler(10, 5, 0, 1)

	sch.bulk.slots[0].active.Store(7)
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 1 {
		t.Fatalf("bulk liveCount = %d, want 1 while bulk slot has capacity", got)
	}

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

	sch.priority.slots[0].active.Store(4)
	sch.priority.slots[1].active.Store(4)
	sch.priority.slots[2].active.Store(3)
	sch.grow(true)
	if got := sch.priority.liveCount.Load(); got != 3 {
		t.Fatalf("priority liveCount = %d, want 3 while priority slot has capacity", got)
	}

	sch.priority.slots[2].active.Store(4)
	sch.grow(true)
	if got := sch.priority.liveCount.Load(); got != 4 {
		t.Fatalf("priority liveCount = %d, want 4", got)
	}
}

func TestNoGrowthWhileNegativeTiersHaveCapacity(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 5, 2)

	sch.bulk.slots[0].active.Store(16)
	sch.bulk.slots[1].expiring.Store(true)
	sch.bulk.slots[1].active.Store(1)
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 2 {
		t.Fatalf("bulk liveCount = %d, want 2 while expiring slot has capacity", got)
	}

	sch.bulk.slots[1].active.Store(2)
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 3 {
		t.Fatalf("bulk liveCount = %d, want 3 when every tier is saturated", got)
	}
}

func TestGrowWhenOnlyRetiringCapacityRemains(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 0, 2)

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
		sch := newGrowTestScheduler(10, 5, 5, 0)
		for i := range 5 {
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
		sch := newGrowTestScheduler(10, 5, 5, 2)
		for i := range 5 {
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
		sch := newGrowTestScheduler(10, 5, 5, 2)
		for i := range 5 {
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
		sch := newGrowTestScheduler(14, 5, 5, 9)
		sch.priority.slots[0].active.Store(4)
		sch.priority.slots[1].active.Store(4)
		sch.priority.slots[2].active.Store(4)
		sch.priority.slots[2].heavy.Store(1)
		sch.priority.slots[3].active.Store(4)
		sch.priority.slots[3].heavy.Store(1)
		sch.priority.slots[4].active.Store(3)
		sch.priority.slots[4].heavy.Store(1)
		for i := range 7 {
			sch.bulk.slots[i].active.Store(1)
		}
		sch.grow(true)
		if got := sch.bulk.liveCount.Load(); got != 9 {
			t.Fatalf("bulk liveCount = %d, want 9 (sibling must not be inflated)", got)
		}
	})

	t.Run("bulk pool full grows unactivated priority pool", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 0, 5)
		for i := range 5 {
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
		for i := range 5 {
			sch.priority.slots[i].active.Store(4)
			sch.bulk.slots[i].active.Store(8)
		}
		sch.grow(true)
		if got := sch.priority.liveCount.Load() + sch.bulk.liveCount.Load(); got != 10 {
			t.Fatalf("total liveCount = %d, want 10 (both pools at their caps)", got)
		}
	})
}

// 防回归：并发生长必须在写锁下重新评估，恰好一个生长方报告生长。
func TestGrowConcurrent(t *testing.T) {
	t.Run("concurrent growers activate the sibling once", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 5, 0)
		for i := range 5 {
			sch.priority.slots[i].active.Store(4)
		}
		const n = 64
		var wg sync.WaitGroup
		var grown atomic.Int64
		wg.Add(n)
		for range n {
			go func() {
				defer wg.Done()
				if pool, _ := sch.grow(true); pool != nil {
					grown.Add(1)
				}
			}()
		}
		wg.Wait()
		if got := sch.bulk.liveCount.Load(); got != 2 {
			t.Fatalf("bulk liveCount = %d, want 2 (single first activation under concurrency)", got)
		}
		if got := grown.Load(); got != 1 {
			t.Fatalf("grow reported growth %d times, want 1 (only the activating request)", got)
		}
	})

	t.Run("concurrent growers add at most one slot", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 5, 2)
		for i := range 5 {
			sch.priority.slots[i].active.Store(4)
		}
		sch.bulk.slots[0].active.Store(8)
		sch.bulk.slots[1].active.Store(8)
		const n = 64
		var wg sync.WaitGroup
		var grown atomic.Int64
		wg.Add(n)
		for range n {
			go func() {
				defer wg.Done()
				if pool, _ := sch.grow(true); pool != nil {
					grown.Add(1)
				}
			}()
		}
		wg.Wait()
		if got := sch.bulk.liveCount.Load(); got != 3 {
			t.Fatalf("bulk liveCount = %d, want 3 (at most one slot added under concurrency)", got)
		}
		if got := grown.Load(); got != 1 {
			t.Fatalf("grow reported growth %d times, want 1 (only the activating request)", got)
		}
	})
}

func TestGrowReturnValue(t *testing.T) {
	t.Run("nil while the pool has tier capacity", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 1, 1)
		sch.priority.slots[0].active.Store(3)
		if pool, live := sch.grow(true); pool != nil {
			t.Fatalf("grow returned pool=%p live=%d with capacity left", pool, live)
		}
	})

	t.Run("grows own pool once saturated", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 1, 1)
		sch.priority.slots[0].active.Store(4)
		pool, live := sch.grow(true)
		if pool != sch.priority {
			t.Fatalf("grow returned %v, want the priority pool", pool)
		}
		if live != 2 {
			t.Fatalf("live = %d, want 2", live)
		}
		if got := sch.priority.liveCount.Load(); got != 2 {
			t.Fatalf("priority liveCount = %d, want 2", got)
		}
	})

	t.Run("first activation reports 2 slots", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 0, 0)
		pool, live := sch.grow(false)
		if pool != sch.bulk {
			t.Fatalf("grow returned %v, want the bulk pool", pool)
		}
		if live != 2 {
			t.Fatalf("live = %d, want 2 on first activation", live)
		}
	})

	t.Run("cross-pool growth reports the sibling pool", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 5, 0)
		for i := range 5 {
			sch.priority.slots[i].active.Store(4)
		}
		pool, live := sch.grow(true)
		if pool != sch.bulk {
			t.Fatalf("grow returned %v, want the bulk (sibling) pool", pool)
		}
		if live != 2 {
			t.Fatalf("live = %d, want 2 (first bulk activation)", live)
		}
	})

	t.Run("nil when both pools are at their caps", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 5, 5)
		for i := range 5 {
			sch.priority.slots[i].active.Store(4)
			sch.bulk.slots[i].active.Store(8)
		}
		if pool, live := sch.grow(true); pool != nil {
			t.Fatalf("grow returned pool=%p live=%d with both pools at their caps", pool, live)
		}
	})
}

func TestGrowFirstActivationPerPool(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 0, 0)

	sch.grow(true)
	if got := sch.priority.liveCount.Load(); got != 2 {
		t.Fatalf("priority liveCount = %d, want 2 on first activation", got)
	}
	if got := sch.bulk.liveCount.Load(); got != 0 {
		t.Fatalf("bulk liveCount = %d, want 0 (lazy, not yet used)", got)
	}

	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 2 {
		t.Fatalf("bulk liveCount = %d, want 2 on first activation", got)
	}
}

func TestGrowResetsRevivedSlotState(t *testing.T) {
	// shrink/retire 把槽位移出存活集合却不清理标记，重新激活的槽位会被判成过期
	// 并保持 degraded 到首次拨号完成。
	sch := newGrowTestScheduler(6, 3, 0, 0)
	sch.bulk.slots[0].degraded.Store(true)
	sch.bulk.slots[0].expiring.Store(true)
	sch.bulk.slots[0].expireAt.Store(time.Now().Add(-time.Minute).UnixNano())
	sch.bulk.slots[0].connBytes.Store(1024)
	sch.bulk.slots[1].degraded.Store(true)
	sch.bulk.slots[1].expireAt.Store(time.Now().Add(-time.Minute).UnixNano())

	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 2 {
		t.Fatalf("bulk liveCount = %d, want 2 on first activation", got)
	}
	lc := &slotLifecycle{connLifetime: time.Minute}
	for i, s := range []*transportSlot{sch.bulk.slots[0], sch.bulk.slots[1]} {
		if s.degraded.Load() {
			t.Fatalf("slot %d: degraded must be cleared on revival", i)
		}
		if s.expiring.Load() {
			t.Fatalf("slot %d: expiring must be cleared on revival", i)
		}
		if s.expireAt.Load() != 0 {
			t.Fatalf("slot %d: expireAt = %d, want 0 until dialed", i, s.expireAt.Load())
		}
		if s.connBytes.Load() != 0 {
			t.Fatalf("slot %d: connBytes = %d, want 0", i, s.connBytes.Load())
		}
		if lc.rotationDue(s, time.Now()) {
			t.Fatalf("slot %d: revived slot without a connection must not be due for rotation", i)
		}
		if slotTierOf(s) != tierActive {
			t.Fatalf("slot %d: tier = %v, want tierActive", i, slotTierOf(s))
		}
	}
	if got := sch.pick(false); got != sch.bulk.slots[0] {
		t.Fatalf("pick(false) = slot %d, want revived bulk slot 0", got.idx)
	}
}

func TestRemoveShrinksLiveCountAndLocatesPool(t *testing.T) {
	s0 := slotWithPool(&http.Transport{})
	s0.active.Store(1)
	s1 := slotWithPool(&http.Transport{})
	s1.degraded.Store(true)
	sch := newScheduler(2, []*transportSlot{s0, s1}, 4, 1) // priority 1, bulk 1
	sch.priority.liveCount.Store(1)
	sch.bulk.liveCount.Store(1)

	if !sch.remove(s1) {
		t.Fatal("idle bulk slot must be removable")
	}
	if got := sch.bulk.liveCount.Load(); got != 0 {
		t.Fatalf("bulk liveCount = %d, want 0", got)
	}
	if got := sch.priority.liveCount.Load(); got != 1 {
		t.Fatalf("priority liveCount = %d, want 1 (untouched)", got)
	}

	if sch.remove(s0) {
		t.Fatal("busy slot must not be removable")
	}
	if got := sch.priority.liveCount.Load(); got != 1 {
		t.Fatalf("priority liveCount = %d, want 1", got)
	}
}
