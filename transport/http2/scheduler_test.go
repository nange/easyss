package http2

import (
	"net/http"
	"testing"
)

// newTestScheduler builds a live scheduler with explicit active/heavy
// counters. Transport structs inside slots are left nil — scheduling tests
// never dial.
func newTestScheduler(specs ...[2]int32) *slotScheduler {
	slots := make([]*transportSlot, len(specs))
	for i, s := range specs {
		slots[i] = &transportSlot{}
		slots[i].active.Store(s[0])
		slots[i].heavy.Store(s[1])
	}
	sch := newScheduler(len(slots), slots, 4, 1)
	sch.liveCount.Store(int32(len(slots)))
	return sch
}

func TestLeastActiveInRangeSkipsHeavy(t *testing.T) {
	t.Run("prefers non-heavy slot", func(t *testing.T) {
		sch := newTestScheduler([2]int32{5, 1}, [2]int32{2, 0})
		if got := sch.leastActiveInRange(0, 2); got != sch.slots[1] {
			t.Fatalf("expected non-heavy slot 1, got active=%d heavy=%d", got.active.Load(), got.heavy.Load())
		}
	})

	t.Run("picks least active among non-heavy", func(t *testing.T) {
		sch := newTestScheduler([2]int32{5, 0}, [2]int32{2, 1}, [2]int32{3, 0})
		if got := sch.leastActiveInRange(0, 3); got != sch.slots[2] {
			t.Fatalf("expected least-active non-heavy slot 2, got active=%d heavy=%d", got.active.Load(), got.heavy.Load())
		}
	})

	t.Run("falls back to least active when all heavy", func(t *testing.T) {
		sch := newTestScheduler([2]int32{5, 1}, [2]int32{2, 1})
		if got := sch.leastActiveInRange(0, 2); got != sch.slots[1] {
			t.Fatalf("expected least-active slot 1, got active=%d heavy=%d", got.active.Load(), got.heavy.Load())
		}
	})

	t.Run("respects liveCount bound", func(t *testing.T) {
		sch := newTestScheduler([2]int32{5, 0}, [2]int32{2, 0}, [2]int32{3, 0})
		sch.liveCount.Store(2)
		if got := sch.leastActiveInRange(0, 3); got != sch.slots[1] {
			t.Fatalf("expected slot 1 within live range, got active=%d", got.active.Load())
		}
	})
}

func TestLeastActiveInRangePrefersHealthyOverDegraded(t *testing.T) {
	t.Run("skips degraded slot when healthy exists", func(t *testing.T) {
		sch := newTestScheduler([2]int32{2, 0}, [2]int32{1, 0})
		sch.slots[1].degraded.Store(true)
		if got := sch.leastActiveInRange(0, 2); got != sch.slots[0] {
			t.Fatalf("expected healthy slot 0, got active=%d heavy=%d degraded=%v", got.active.Load(), got.heavy.Load(), got.degraded.Load())
		}
	})

	t.Run("prefers heavy-but-not-degraded over degraded", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 1}, [2]int32{3, 1})
		sch.slots[1].degraded.Store(true)
		if got := sch.leastActiveInRange(0, 2); got != sch.slots[0] {
			t.Fatalf("expected non-degraded slot 0, got active=%d degraded=%v", got.active.Load(), got.degraded.Load())
		}
	})

	t.Run("falls back to degraded when nothing else", func(t *testing.T) {
		sch := newTestScheduler([2]int32{5, 1}, [2]int32{3, 1})
		sch.slots[0].degraded.Store(true)
		sch.slots[1].degraded.Store(true)
		if got := sch.leastActiveInRange(0, 2); got != sch.slots[1] {
			t.Fatalf("expected least-active degraded slot 1, got active=%d", got.active.Load())
		}
	})
}

func TestLeastActiveInRangePrefersNonExpiring(t *testing.T) {
	t.Run("skips expiring slot when fresh exists", func(t *testing.T) {
		sch := newTestScheduler([2]int32{2, 0}, [2]int32{1, 0})
		sch.slots[1].expiring.Store(true)
		if got := sch.leastActiveInRange(0, 2); got != sch.slots[0] {
			t.Fatalf("expected non-expiring slot 0, got active=%d expiring=%v", got.active.Load(), got.expiring.Load())
		}
	})

	t.Run("prefers degraded-but-fresh over expiring", func(t *testing.T) {
		sch := newTestScheduler([2]int32{3, 1}, [2]int32{1, 1})
		sch.slots[0].degraded.Store(true)
		sch.slots[1].expiring.Store(true)
		if got := sch.leastActiveInRange(0, 2); got != sch.slots[0] {
			t.Fatalf("expected degraded slot 0 over expiring, got active=%d", got.active.Load())
		}
	})

	t.Run("falls back to expiring when nothing else", func(t *testing.T) {
		sch := newTestScheduler([2]int32{5, 1}, [2]int32{3, 1})
		sch.slots[0].expiring.Store(true)
		sch.slots[1].expiring.Store(true)
		if got := sch.leastActiveInRange(0, 2); got != sch.slots[1] {
			t.Fatalf("expected least-active expiring slot 1, got active=%d", got.active.Load())
		}
	})
}

func TestNeedsMore(t *testing.T) {
	t.Run("heavy slot with single stream does not block growth", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 1}, [2]int32{8, 0})
		// slot0 is heavy with 1 stream (below threshold), slot1 eligible at
		// threshold: growth must be allowed since new streams avoid slot0.
		if !sch.needsMore(0, 2, 4) {
			t.Fatal("expected growth with heavy slot below threshold")
		}
	})

	t.Run("eligible slot below threshold blocks growth", func(t *testing.T) {
		sch := newTestScheduler([2]int32{3, 0}, [2]int32{8, 0})
		if sch.needsMore(0, 2, 4) {
			t.Fatal("expected no growth while an eligible slot has capacity")
		}
	})

	t.Run("all slots heavy still grows", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 1}, [2]int32{1, 1})
		if !sch.needsMore(0, 2, 4) {
			t.Fatal("expected growth when no eligible slot exists")
		}
	})

	t.Run("degraded and expiring slots do not block growth", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 0}, [2]int32{8, 0})
		sch.slots[0].degraded.Store(true)
		if !sch.needsMore(0, 2, 4) {
			t.Fatal("expected growth with degraded slot below threshold")
		}
		sch2 := newTestScheduler([2]int32{1, 0}, [2]int32{8, 0})
		sch2.slots[0].expiring.Store(true)
		if !sch2.needsMore(0, 2, 4) {
			t.Fatal("expected growth with expiring slot below threshold")
		}
	})
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
