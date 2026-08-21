package http2

import (
	"testing"
)

func TestSlotStatus(t *testing.T) {
	tests := []struct {
		name   string
		heavy  int32
		deg    bool
		exp    bool
		expect string
	}{
		{name: "no flags is active", expect: "active"},
		{name: "heavy", heavy: 1, expect: "heavy"},
		{name: "degraded", deg: true, expect: "degraded"},
		{name: "expiring", exp: true, expect: "expiring"},
		{name: "heavy and expiring", heavy: 1, exp: true, expect: "heavy+expiring"},
		{name: "degraded and heavy", heavy: 2, deg: true, expect: "heavy+degraded"},
		{name: "all flags", heavy: 1, deg: true, exp: true, expect: "heavy+degraded+expiring"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &transportSlot{}
			s.heavy.Store(tt.heavy)
			s.degraded.Store(tt.deg)
			s.expiring.Store(tt.exp)
			if got := slotStatus(s); got != tt.expect {
				t.Fatalf("slotStatus() = %q, want %q", got, tt.expect)
			}
		})
	}
}

// newTestScheduler puts every spec into the priority pool and leaves the
// bulk pool empty, so these rendering tests exercise one pool only.
func TestSlotStatusString(t *testing.T) {
	// statusString renders with the caller's liveCount snapshot, exactly
	// like Stats() does.
	statusString := func(sch *slotScheduler) string {
		return slotStatusString(sch, int(sch.priority.liveCount.Load()), int(sch.bulk.liveCount.Load()))
	}

	t.Run("empty live set", func(t *testing.T) {
		sch := newTestScheduler()
		if got := statusString(sch); got != "[]" {
			t.Fatalf("slotStatusString() = %q, want %q", got, "[]")
		}
	})

	t.Run("all active with stream counts", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 0}, [2]int32{2, 0})
		if got, want := statusString(sch), "[0:1:active, 1:2:active]"; got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("mixed states", func(t *testing.T) {
		sch := newTestScheduler([2]int32{3, 0}, [2]int32{2, 0}, [2]int32{1, 0}, [2]int32{1, 1})
		sch.priority.slots[0].degraded.Store(true)
		sch.priority.slots[1].expiring.Store(true)
		want := "[0:3:degraded, 1:2:expiring, 2:1:active, 3:1:heavy]"
		if got := statusString(sch); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("combined flags", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 1}, [2]int32{0, 0})
		sch.priority.slots[0].expiring.Store(true)
		sch.priority.slots[1].degraded.Store(true)
		want := "[0:1:heavy+expiring, 1:0:degraded]"
		if got := statusString(sch); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("respects liveCount bound", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 0}, [2]int32{2, 0}, [2]int32{3, 0})
		sch.priority.slots[2].degraded.Store(true)
		sch.priority.liveCount.Store(2)
		want := "[0:1:active, 1:2:active]"
		if got := statusString(sch); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("scrambled live order is renumbered consecutively", func(t *testing.T) {
		// Simulate a swap-remove of slot 1: positions [0,1,2] now hold
		// slots with real indices 0,3,2 and liveCount dropped to 3. Entries
		// stay ordered by real index but are renumbered 0..n-1, so the
		// output indices never jump.
		sch := newTestScheduler([2]int32{1, 0}, [2]int32{2, 0}, [2]int32{3, 0}, [2]int32{4, 0})
		sch.priority.slots[1], sch.priority.slots[3] = sch.priority.slots[3], sch.priority.slots[1]
		sch.priority.liveCount.Store(3)
		want := "[0:1:active, 1:3:active, 2:4:active]"
		if got := statusString(sch); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("renders both pools merged", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{1, 0}},
			[][2]int32{{2, 0}},
		)
		// Priority slot idx 0, bulk slot idx 1; merged output stays ordered
		// by stable index.
		want := "[0:1:active, 1:2:active]"
		if got := statusString(sch); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})
}
