package http2

import (
	"testing"
)

// BenchmarkPick 比较的锁模式：理想的无锁基线、当前受 RLock 保护的
// Open 路径，以及假设的写锁路径。
const (
	lockNone = iota
	lockRLock
	lockLock
)

// benchScheduler 返回一个 15 槽位调度器（6 priority / 9 bulk，
// threshold 4，与客户端默认一致），带现实的健康状态混合：
// 接近 base 的健康槽位，加上每个池各一个 heavy、expiring、
// degraded 和 retiring 槽位。
func benchScheduler() *slotScheduler {
	slots := make([]*transportSlot, 15)
	for i := range slots {
		slots[i] = &transportSlot{idx: i}
	}
	sch := newScheduler(15, slots, 4, 6)
	sch.priority.liveCount.Store(6)
	sch.bulk.liveCount.Store(9)

	// Priority 池（base 4）：两个健康、一个 heavy、一个 expiring、
	// 一个 degraded、一个 retiring。
	sch.priority.slots[0].active.Store(3)
	sch.priority.slots[1].active.Store(3)
	sch.priority.slots[2].active.Store(1)
	sch.priority.slots[2].heavy.Store(1)
	sch.priority.slots[3].active.Store(1)
	sch.priority.slots[3].expiring.Store(true)
	sch.priority.slots[4].active.Store(1)
	sch.priority.slots[4].degraded.Store(true)
	sch.priority.slots[5].degraded.Store(true)
	sch.priority.slots[5].expiring.Store(true)

	// Bulk 池（base 8）：三个健康、一个 heavy、一个 expiring、
	// 一个 degraded、三个 retiring。
	for i := range 3 {
		sch.bulk.slots[i].active.Store(7)
	}
	sch.bulk.slots[3].active.Store(1)
	sch.bulk.slots[3].heavy.Store(1)
	sch.bulk.slots[4].active.Store(1)
	sch.bulk.slots[4].expiring.Store(true)
	sch.bulk.slots[5].active.Store(1)
	sch.bulk.slots[5].degraded.Store(true)
	for i := 6; i < 9; i++ {
		sch.bulk.slots[i].degraded.Store(true)
		sch.bulk.slots[i].expiring.Store(true)
	}
	return sch
}

// pickSaturation 把池提升到给定的压力状态，让基准测试覆盖特定的
// 调度路径：
//
//	level0     — 健康槽位低于 base：pick 返回活跃流最少的健康槽位；
//	level1     — 健康槽位在 base：分层搜索遍历 expiring/heavy/degraded
//	             层级；
//	saturated  — 每个层级都达容量：运行无上限的 leastActive fallback
//	             （retiring 槽位被排除）。
func pickSaturation(sch *slotScheduler, mode string) {
	switch mode {
	case "level1":
		sch.priority.slots[0].active.Store(4)
		sch.priority.slots[1].active.Store(4)
		for i := range 3 {
			sch.bulk.slots[i].active.Store(8)
		}
	case "saturated":
		sch.priority.slots[0].active.Store(4)
		sch.priority.slots[1].active.Store(4)
		sch.priority.slots[2].active.Store(2) // heavy：2×4 = 8 ≥ base 4
		sch.priority.slots[3].active.Store(1) // expiring：1×8 = 8 ≥ base 4
		sch.priority.slots[4].active.Store(1) // degraded：1×16 = 16 ≥ base 4
		for i := range 3 {
			sch.bulk.slots[i].active.Store(8)
		}
		sch.bulk.slots[3].active.Store(4) // heavy：4×4 = 16 ≥ base 8
		sch.bulk.slots[4].active.Store(2) // expiring：2×8 = 16 ≥ base 8
		sch.bulk.slots[5].active.Store(2) // degraded：2×16 = 32 ≥ base 8
	}
}

// benchPick 在给定锁模式下测量一次 pick（加上真实 Open 路径执行的
// active 记账）。每次迭代后恢复 active 计数器，使池快照在整个
// 运行期间保持稳定。
func benchPick(b *testing.B, mode string, lockMode int) {
	sch := benchScheduler()
	pickSaturation(sch, mode)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			switch lockMode {
			case lockNone:
				slot := sch.pick(false)
				slot.active.Add(1)
				slot.active.Add(-1)
			case lockRLock:
				sch.mu.RLock()
				slot := sch.pick(false)
				slot.active.Add(1)
				sch.mu.RUnlock()
				slot.active.Add(-1)
			case lockLock:
				sch.mu.Lock()
				slot := sch.pick(false)
				slot.active.Add(1)
				sch.mu.Unlock()
				slot.active.Add(-1)
			}
		}
	})
}

// BenchmarkPick 比较三种锁模式在三种压力状态下的调度成本：
// 运行 `go test -bench=BenchmarkPick -cpu=1,4,8 ./transport/http2/`
func BenchmarkPick(b *testing.B) {
	modes := []struct {
		name string
		lock int
	}{
		{"NoLock", lockNone},
		{"RLock", lockRLock},
		{"Lock", lockLock},
	}
	for _, mode := range []string{"level0", "level1", "saturated"} {
		for _, lm := range modes {
			b.Run(mode+"/"+lm.name, func(b *testing.B) {
				benchPick(b, mode, lm.lock)
			})
		}
	}
}
