package http2

import (
	"testing"
)

// Lock modes compared by BenchmarkPick: the ideal no-lock baseline, the
// current RLock-protected Open path, and the hypothetical write-lock path.
const (
	lockNone = iota
	lockRLock
	lockLock
)

// benchScheduler returns a 15-slot scheduler (6 priority / 9 bulk,
// threshold 4, matching the client defaults) with a realistic mix of
// health states: healthy slots near the base, plus one heavy, one
// expiring, one degraded and one retiring slot per pool.
func benchScheduler() *slotScheduler {
	slots := make([]*transportSlot, 15)
	for i := range slots {
		slots[i] = &transportSlot{idx: i}
	}
	sch := newScheduler(15, slots, 4, 6)
	sch.priority.liveCount.Store(6)
	sch.bulk.liveCount.Store(9)

	// Priority pool (base 4): two healthy, one heavy, one expiring, one
	// degraded, one retiring.
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

	// Bulk pool (base 8): three healthy, one heavy, one expiring, one
	// degraded, three retiring.
	for i := 0; i < 3; i++ {
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

// pickSaturation raises the pools to the given pressure state so the
// benchmark exercises a specific scheduling path:
//
//	level0     — healthy slots below the base: pick returns the
//	             least-active healthy slot;
//	level1     — healthy slots at the base: the tiered search walks the
//	             expiring/heavy/degraded tiers;
//	saturated  — every tier at capacity: the uncapped leastActive
//	             fallback runs (retiring slots excluded).
func pickSaturation(sch *slotScheduler, mode string) {
	switch mode {
	case "level1":
		sch.priority.slots[0].active.Store(4)
		sch.priority.slots[1].active.Store(4)
		for i := 0; i < 3; i++ {
			sch.bulk.slots[i].active.Store(8)
		}
	case "saturated":
		sch.priority.slots[0].active.Store(4)
		sch.priority.slots[1].active.Store(4)
		sch.priority.slots[2].active.Store(2) // heavy: 2×4 = 8 ≥ base 4
		sch.priority.slots[3].active.Store(1) // expiring: 1×8 = 8 ≥ base 4
		sch.priority.slots[4].active.Store(1) // degraded: 1×16 = 16 ≥ base 4
		for i := 0; i < 3; i++ {
			sch.bulk.slots[i].active.Store(8)
		}
		sch.bulk.slots[3].active.Store(4) // heavy: 4×4 = 16 ≥ base 8
		sch.bulk.slots[4].active.Store(2) // expiring: 2×8 = 16 ≥ base 8
		sch.bulk.slots[5].active.Store(2) // degraded: 2×16 = 32 ≥ base 8
	}
}

// benchPick measures one pick (plus the active accounting the real Open
// path performs) under the given lock mode. The active counter is
// restored after each iteration so the pool snapshot stays stable across
// the whole run.
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

// BenchmarkPick compares the scheduling cost under the three lock modes
// across the three pressure states: `go test -bench=BenchmarkPick -cpu=1,4,8 ./transport/http2/`
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
