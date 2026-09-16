package http2

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestPool 构建一个带显式 active/heavy 计数器的单活池。
// 槽位内的 Transport 结构体留空——调度测试从不拨号。
// liveCount 被设置为 specs 的数量。
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

// newTestScheduler 构建一个调度器：其 priority 池持有全部给定 specs（存活），
// bulk 池为空。threshold 为 4，因此 priority 池的 base 是 4，bulk 池的 base 是 8。
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

// newTwoPoolScheduler 通过生产构造函数构建调度器，并给定每个池的 specs：
// 前 len(pSpecs) 项构成 priority 池（base 4），其余构成 bulk 池（base 8）。
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

// TestSchedulerSingleSlot 覆盖 maxSlots == 1 的退化拆分：bulk 池必须保持为空
// （maxSlots 0），这样 poolOf 会回退到 priority 池，而不是索引一个空的
// 槽位数组（回归测试：bulk 流曾经以 index out of range 崩溃）。
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

	// bulk 增长绝不能激活超过 priority 池所拥有的槽位数。
	sch.grow(false)
	if got := int(sch.priority.liveCount.Load()); got != 1 {
		t.Fatalf("priority liveCount = %d, want 1", got)
	}
	if got := int(sch.bulk.liveCount.Load()); got != 0 {
		t.Fatalf("bulk liveCount = %d, want 0", got)
	}

	// 饱和唯一的 priority 槽位：pick 绝不能尝试向空的 bulk 池借用
	// （回归测试：在空池上执行 tieredSelect 会以 index out of range 崩溃）。
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
			{[]int32{7, 7}, 0},   // 低于 base
			{[]int32{8, 8}, 1},   // 首个阈值
			{[]int32{15, 15}, 1}, // 仍低于 2x base
			{[]int32{16, 16}, 2}, // 2x base
			{[]int32{31, 31}, 2}, // 低于 4x base
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
		// active 层为空：池最小值（0）被钳制到 base，因此级别在 1 而非 0 处生效。
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
		{tierActive, 0, 8, 8},   // 级别 0：active 最多承载到 base
		{tierActive, 1, 8, 0},   // 级别>=1：active 只由 fallback 承接
		{tierExpiring, 0, 8, 0}, // 级别 0 时负向层级禁用
		// 级别 1 的加权负载容量：heavy 槽位最多承载 base/4 条流（权重 4），
		// expiring 为 base/8（权重 8），degraded 为 base/16（权重 16）——
		// 1 条 heavy 流相当于 4 条健康流，1 条 degraded 相当于 16，
		// 1 条 expiring 相当于 8。
		{tierExpiring, 1, 8, 8},
		{tierHeavy, 1, 8, 8},
		{tierDegraded, 1, 8, 8},
		{tierExpiring, 2, 8, 16}, // 翻倍
		{tierExpiring, 3, 8, 32}, // 再次翻倍
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
		// 健康槽位低于 base 时，绝不能选择空闲的 expiring 槽位：
		// 优先使用健康连接。
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
		// 单条 expiring 流权重 8 = 层级容量：级别 1 的 expiring 层级不再
		// 接受新流，因此该流溢出到 heavy 槽位（1 条流权重 4 < 8）。
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
		// 含 2 条流的 heavy 槽位权重 8 = 层级容量：所有负向层级都已满，
		// 因此池回退到负载最少的健康槽位。
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
		// 一条 degraded 流权重 16 >= 层级容量：degraded 层级已满，
		// 因此池回退到负载最少的槽位——健康的那个（平局按 negativeScore 打破）。
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
		// 每个层级都已达容量（加权负载 32/16/32 >= 8）；回退目标是按加权负载
		// 计算的最少负载槽位，平局按 negativeScore 打破。
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
		// 1 条 expiring 流权重 8 < 翻倍后的容量 16：级别 2 时 expiring
		// 层级可承载一条流（级别 1 时已满）。
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
		// 两者都承载 1 条流；仅 heavy 的槽位权重 4 < 8 且开放，
		// heavy+expiring 的槽位权重 32 且已满。
		p := newTestPool(8, [2]int32{8, 0}, [2]int32{1, 1}, [2]int32{1, 1})
		p.slots[2].expiring.Store(true)
		slot, saturated := p.tieredSelect()
		if saturated || slot != p.slots[1] {
			t.Fatalf("got slot %d saturated=%v, want heavy-only slot 1", slot.idx, saturated)
		}
	})

	t.Run("among degraded slots prefers degraded-only over degraded+heavy", func(t *testing.T) {
		// 级别 3（容量 32）：单条 degraded 流（权重 16）仍开放，
		// 而 degraded+heavy（权重 32）已满。
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
		// 级别 3（容量 32）：expiring/heavy 层级已满，单条 degraded 流
		// （权重 16 < 32）仍开放；空闲的 retiring 槽位被排除，绝不能赢得该层级。
		p := newTestPool(8, [2]int32{32, 0}, [2]int32{4, 0}, [2]int32{8, 0}, [2]int32{0, 0}, [2]int32{1, 0})
		p.slots[1].expiring.Store(true)
		p.slots[2].heavy.Store(1)
		p.slots[3].degraded.Store(true)
		p.slots[3].expiring.Store(true) // 空闲 retiring 槽位：被排除
		p.slots[4].degraded.Store(true)
		// 空闲 retiring 槽位绝不能赢得 degraded 层级：retiring 槽位被排除，
		// 因此承载一条流的仅 degraded 槽位被选中。
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
		// 每个层级都已达容量；空闲 retiring 槽位（下限权重 128）本就不会是
		// 全局负载最少的槽位，但无论如何都必须越过它，选择负载最少的健康槽位。
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
		// 没有其他选择：pick 绝不能失败，因此返回负载最少的 retiring 槽位
		// （健康循环很快会把两者都退役）；空闲的那个（下限权重 128）
		// 胜过忙碌的那个（256）。
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
		// 两者权重都是 128（空闲槽位按下限标记权重计）：平局归于忙碌槽位，
		// 使空闲槽位保持空闲，由健康循环将其退役而不是被重新激活。
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
		// 健康槽位在 base（级别 1）而 expiring 槽位空闲——draining：
		// 层级搜索跳过它，fallback 也排除它，因此该流落在健康槽位上，
		// 池报告饱和（随后 grow 拨号新连接，而不是重新激活疲惫的连接）。
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want healthy slot 0 with saturated=true", slot.idx, saturated)
		}
	})

	t.Run("busy degraded slot preferred over idle degraded slot", func(t *testing.T) {
		// 级别 3（容量 32）：单条 degraded 流（权重 16）仍开放；
		// 空闲的那个处于 draining，被跳过。
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
		// 每个层级都已达容量；空闲 expiring 槽位（下限权重 8）本会是全局
		// 负载最少的槽位，但它处于 draining，必须越过它选择负载最少的
		// 健康槽位。
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want fallback slot 0 with saturated=true", slot.idx, saturated)
		}
	})

	t.Run("all live slots draining returns the least-loaded draining slot", func(t *testing.T) {
		p := newTestPool(8, [2]int32{0, 0}, [2]int32{0, 0})
		p.slots[0].expiring.Store(true)
		p.slots[1].degraded.Store(true)
		// 没有其他选择：pick 绝不能失败，因此返回负载最少的 draining 槽位
		// （健康循环很快会轮换/退役它们）；空闲 expiring 槽位（权重 8）
		// 胜过空闲 degraded 槽位（权重 16）。
		slot, saturated := p.tieredSelect()
		if !saturated || slot != p.slots[0] {
			t.Fatalf("got slot %d saturated=%v, want least-loaded draining slot 0", slot.idx, saturated)
		}
	})
}

func TestGrowReplacesDrainingSlot(t *testing.T) {
	// 一个在 base 的健康槽位加一个空闲 expiring 槽位：draining 槽位
	// 被排除在选择之外，因此池计为饱和，随后生长一条新连接，
	// 而不是重新激活疲惫的连接。
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
	// bulk 池唯一不 draining 的槽位在 base；空闲 expiring 槽位处于
	// draining，不得被借用——该流停留在本池的 fallback 上。
	if got := sch.pick(true); got != sch.priority.slots[0] {
		t.Fatalf("pick(true) = slot %d, want own pool fallback slot 0", got.idx)
	}
}

func TestTieredSelectNoHealthyEngagesLowerTiers(t *testing.T) {
	t.Run("all expiring picks the busy slot over the idle draining one", func(t *testing.T) {
		p := newTestPool(8, [2]int32{0, 0}, [2]int32{1, 0})
		p.slots[0].expiring.Store(true)
		p.slots[1].expiring.Store(true)
		// 槽位 0 空闲且 expiring——draining：新流不得重新激活它
		// （重新激活会推迟它的轮换）。忙碌的 expiring 槽位 1 也已满
		// （1 条流权重 8 = 层级容量），因此 fallback 仍落在它上面——
		// 唯一不 draining 的候选——池报告饱和，于是 grow 拨号一条
		// 新连接，而不是重新激活任一疲惫的槽位。
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
	// 两个各 5 条流的健康槽位：对 priority 流（base 4）已饱和，
	// 对 bulk 流（base 8）仍开放。
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
			[][2]int32{{4, 0}}, // priority 池在 base 4 处饱和
			[][2]int32{{1, 0}, {2, 0}},
		)
		sch.bulk.slots[0].expiring.Store(true)
		// bulk 池健康层中负载最少的是 active=2 的槽位。
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
		// bulk 池：健康层在 16（级别 2）-> expiring 层级
		// （active=1，权重 8 < 16）。
		if got := sch.pick(true); got != sch.bulk.slots[1] {
			t.Fatalf("pick(true) = slot %d, want borrowed expiring bulk slot 1", got.idx)
		}
	})

	t.Run("bulk borrows healthy priority slot", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{1, 0}},
			[][2]int32{{8, 0}}, // bulk 池在 base 8 处饱和
		)
		// priority 池有健康容量（active=1 < 4）。
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
		// priority 池饱和（heavy 槽位 8 条流，fallback 权重 32）；bulk 池
		// 同样饱和（heavy 槽位 2/8 条流，权重 8/32 >= base 8），但其
		// fallback 槽位承载 2 条流（权重 8），对比我们的 32——新流必须
		// 去那里，而不是堆到 8 条流的槽位上。
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
		// priority 池：heavy 槽位 2 条流，权重 8 = 其 base 4 的 2 倍，
		// 因此饱和并回退到槽位 0（权重 8）。bulk 池：heavy 槽位 4/8 条流
		// （权重 16/32）同样饱和，其 fallback 在 4 条流——负载并不更小，
		// 因此该流留在本池。
		if got := sch.pick(true); got != sch.priority.slots[0] {
			t.Fatalf("pick(true) = slot %d, want own pool fallback slot 0", got.idx)
		}
	})
}

func TestPickExcludesRetiringInBorrow(t *testing.T) {
	t.Run("borrows healthy bulk slot over idle retiring bulk slot", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{4, 0}}, // priority 池在 base 4 处饱和
			[][2]int32{{0, 0}, {1, 0}},
		)
		sch.bulk.slots[0].degraded.Store(true)
		sch.bulk.slots[0].expiring.Store(true)
		// 空闲 retiring 的 bulk 槽位绝不能赢得借用：改为借用健康的
		// bulk 槽位（active=1）。
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
		// bulk 池整体处于 retiring：其 fallback（忙碌槽位，权重 128——
		// 空闲槽位被钳制到相同的 128）超过本池 fallback（权重 4），
		// 因此该流留在本池，而不是重新激活一条注定要退役的连接。
		if got := sch.pick(true); got != sch.priority.slots[0] {
			t.Fatalf("pick(true) = slot %d, want own pool fallback slot 0", got.idx)
		}
	})
}

// newGrowTestScheduler 通过生产构造函数构建调度器：共 maxSlots 个槽位，
// 其中 prioritySlots 个为 priority 类，threshold 4，并按给定每池存活数
// （其余槽位作为 bulk 存活）。
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
	// priority 池有 5 个槽位（0-4），bulk 池 5 个（5-9）。仅一个 bulk 槽位存活。
	sch := newGrowTestScheduler(10, 5, 0, 1)

	// bulk 槽位低于 bulk 阈值（8）：不生长。
	sch.bulk.slots[0].active.Store(7)
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 1 {
		t.Fatalf("bulk liveCount = %d, want 1 while bulk slot has capacity", got)
	}

	// bulk 槽位饱和：生长——与（空的）priority 池无关，
	// 每个池按各自需求独立生长。
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

	// priority 槽位低于阈值（4）：不生长。
	sch.priority.slots[0].active.Store(4)
	sch.priority.slots[1].active.Store(4)
	sch.priority.slots[2].active.Store(3)
	sch.grow(true)
	if got := sch.priority.liveCount.Load(); got != 3 {
		t.Fatalf("priority liveCount = %d, want 3 while priority slot has capacity", got)
	}

	// 所有存活 priority 槽位到达阈值：生长。
	sch.priority.slots[2].active.Store(4)
	sch.grow(true)
	if got := sch.priority.liveCount.Load(); got != 4 {
		t.Fatalf("priority liveCount = %d, want 4", got)
	}
}

func TestNoGrowthWhileNegativeTiersHaveCapacity(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 5, 2)

	// 级别 1 时 expiring 槽位单条流即满，因此容量检查在级别 2 进行
	// （健康槽位在 16）：expiring 槽位仍有容量（1 条流权重 8 < 16），
	// 该流在那里得到服务，不生长。
	sch.bulk.slots[0].active.Store(16)
	sch.bulk.slots[1].expiring.Store(true)
	sch.bulk.slots[1].active.Store(1)
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 2 {
		t.Fatalf("bulk liveCount = %d, want 2 while expiring slot has capacity", got)
	}

	// 负向层级也饱和（2 条 expiring 流权重 16 >= 16）：生长。
	sch.bulk.slots[1].active.Store(2)
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 3 {
		t.Fatalf("bulk liveCount = %d, want 3 when every tier is saturated", got)
	}
}

func TestGrowWhenOnlyRetiringCapacityRemains(t *testing.T) {
	sch := newGrowTestScheduler(10, 5, 0, 2)

	// 一个健康槽位在 8 处饱和；另一个槽位 retiring（degraded+expiring）
	// 且空闲。其加权负载为 0，但 retiring 槽位被排除在选择之外，
	// 因此池计为饱和，生长一条新连接来替换这个注定失败的槽位。
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
		// priority 池（5 槽位）处于上限且每个槽位都在阈值上，bulk 池从未
		// 使用：新 priority 流需要新连接，因此生长兄弟池（带首次激活 +2 语义）。
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
		// 本池处于上限且每个槽位都在阈值（4），兄弟池的槽位也饱和
		// （各 8）：确实需要新连接，因此兄弟池生长。
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
		// 上报的快照：priority 池处于连接上限，但其槽位承载 3-4 条流
		// （健康层最小值低于阈值 4）——priority 槽位仍可服务流时，
		// 绝不能膨胀 bulk 池。
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
		// priority 池饱和，bulk 池有两个 heavy 槽位分别 1 和 8 条流：
		// 1 条流的槽位权重 4 < base 8，因此 bulk 池仍有层级容量——
		// 流借用它而不是生长它。跨池生长受兄弟池自身槽位阈值的节制。
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
		// 上报的快照：priority 池饱和（健康槽位在 4，heavy 槽位在 4/4/3
		// ——3 条 heavy 流权重 12 >= base 4），bulk 池持有七个各 1 条流的
		// 健康槽位：远低于其阈值 8，因此绝不能生长。
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

// TestGrowConcurrent 压力测试 grow 的双检锁：并发的生长方必须在写锁上
// 串行化并在锁下重新评估，因此流突发永远不会过度生长池——且恰好只有一个
// 生长方报告生长（即真正激活了槽位的那个请求）。
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

// TestGrowReturnValue 验证 grow 的报告契约：未生长时返回 nil，
// 否则返回生长后的池及其增长后的存活数——Open 用它把槽位扩容
// 归因于触发它的请求。
func TestGrowReturnValue(t *testing.T) {
	t.Run("nil while the pool has tier capacity", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 1, 1)
		sch.priority.slots[0].active.Store(3) // 低于阈值 4
		if pool, live := sch.grow(true); pool != nil {
			t.Fatalf("grow returned pool=%p live=%d with capacity left", pool, live)
		}
	})

	t.Run("grows own pool once saturated", func(t *testing.T) {
		sch := newGrowTestScheduler(10, 5, 1, 1)
		sch.priority.slots[0].active.Store(4) // 到达阈值
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

	// 首条 priority 流激活 2 条 priority 连接...
	sch.grow(true)
	if got := sch.priority.liveCount.Load(); got != 2 {
		t.Fatalf("priority liveCount = %d, want 2 on first activation", got)
	}
	if got := sch.bulk.liveCount.Load(); got != 0 {
		t.Fatalf("bulk liveCount = %d, want 0 (lazy, not yet used)", got)
	}

	// ...而首条 bulk 流（例如 DNS 查询）激活它自己的 2 条 bulk 连接。
	sch.grow(false)
	if got := sch.bulk.liveCount.Load(); got != 2 {
		t.Fatalf("bulk liveCount = %d, want 2 on first activation", got)
	}
}

func TestGrowResetsRevivedSlotState(t *testing.T) {
	// 被 grow 重新激活的槽位不得继承前一条连接的轮换状态：shrink/retire
	// 通过交换删除把槽位移出存活集合，却不清理其标记，否则重新激活的槽位
	// 会被判为过期（expiring）并保持 degraded，直到其首次拨号完成——
	// 即"新槽位立即过期"的症状。
	sch := newGrowTestScheduler(6, 3, 0, 0)
	// bulk 槽位 0/1 在带着旧连接状态被 shrink 掉：已过期的截止时间、
	// 承载的字节数、degraded/expiring 判定。
	sch.bulk.slots[0].degraded.Store(true)
	sch.bulk.slots[0].expiring.Store(true)
	sch.bulk.slots[0].expireAt.Store(time.Now().Add(-time.Minute).UnixNano())
	sch.bulk.slots[0].connBytes.Store(1024)
	sch.bulk.slots[1].degraded.Store(true)
	sch.bulk.slots[1].expireAt.Store(time.Now().Add(-time.Minute).UnixNano())

	// 首次激活同时重新激活两个槽位，且必须重置两者。
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
	// 重新激活的槽位立即可选择（非 draining/retiring）。
	if got := sch.pick(false); got != sch.bulk.slots[0] {
		t.Fatalf("pick(false) = slot %d, want revived bulk slot 0", got.idx)
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

	// s1 位于 bulk 池（构造函数按池分配索引，remove 通过扫描两个池定位）。
	if !sch.remove(s1) {
		t.Fatal("idle bulk slot must be removable")
	}
	if got := sch.bulk.liveCount.Load(); got != 0 {
		t.Fatalf("bulk liveCount = %d, want 0", got)
	}
	if got := sch.priority.liveCount.Load(); got != 1 {
		t.Fatalf("priority liveCount = %d, want 1 (untouched)", got)
	}

	// 忙碌槽位永不移除。
	if sch.remove(s0) {
		t.Fatal("busy slot must not be removable")
	}
	if got := sch.priority.liveCount.Load(); got != 1 {
		t.Fatalf("priority liveCount = %d, want 1", got)
	}
}
