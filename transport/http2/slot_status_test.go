package http2

import (
	"testing"
)

func TestSlotStatus(t *testing.T) {
	tests := []struct {
		name   string
		active int32
		heavy  int32
		deg    bool
		exp    bool
		expect string
	}{
		{name: "no flags and no streams is idle", active: 0, expect: "idle"},
		{name: "no flags with streams is active", active: 1, expect: "active"},
		{name: "idle expiring", exp: true, expect: "expiring"},
		{name: "heavy", active: 1, heavy: 1, expect: "heavy"},
		{name: "degraded", active: 1, deg: true, expect: "degraded"},
		{name: "expiring", active: 1, exp: true, expect: "expiring"},
		{name: "heavy and expiring", active: 1, heavy: 1, exp: true, expect: "heavy+expiring"},
		{name: "degraded and heavy", active: 1, heavy: 2, deg: true, expect: "heavy+degraded"},
		{name: "all flags", active: 1, heavy: 1, deg: true, exp: true, expect: "heavy+degraded+expiring"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &transportSlot{}
			s.active.Store(tt.active)
			s.heavy.Store(tt.heavy)
			s.degraded.Store(tt.deg)
			s.expiring.Store(tt.exp)
			if got := slotStatus(s, int(tt.active)); got != tt.expect {
				t.Fatalf("slotStatus() = %q, want %q", got, tt.expect)
			}
		})
	}
}

// statusString renders a pool with the caller's liveCount snapshot, exactly
// like Stats() does for each pool.
func statusString(pool *slotPool) string {
	return slotStatusString(pool, int(pool.liveCount.Load()))
}

func TestSlotStatusString(t *testing.T) {
	t.Run("empty live set", func(t *testing.T) {
		sch := newTestScheduler()
		if got := statusString(sch.priority); got != "[]" {
			t.Fatalf("slotStatusString() = %q, want %q", got, "[]")
		}
		if got := statusString(sch.bulk); got != "[]" {
			t.Fatalf("slotStatusString() = %q, want %q", got, "[]")
		}
	})

	t.Run("all active with stream counts", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 0}, [2]int32{2, 0})
		if got, want := statusString(sch.priority), "[0:1:active, 1:2:active]"; got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("idle slots render as idle", func(t *testing.T) {
		sch := newTestScheduler([2]int32{0, 0}, [2]int32{2, 0}, [2]int32{0, 0})
		sch.priority.slots[2].expiring.Store(true)
		// A healthy slot hosting no streams renders as "idle" (warm
		// connection); marks still win over the idle label.
		want := "[0:0:idle, 1:2:active, 2:0:expiring]"
		if got := statusString(sch.priority); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("mixed states", func(t *testing.T) {
		sch := newTestScheduler([2]int32{3, 0}, [2]int32{2, 0}, [2]int32{1, 0}, [2]int32{1, 1})
		sch.priority.slots[0].degraded.Store(true)
		sch.priority.slots[1].expiring.Store(true)
		want := "[0:3:degraded, 1:2:expiring, 2:1:active, 3:1:heavy]"
		if got := statusString(sch.priority); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("combined flags", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 1}, [2]int32{0, 0})
		sch.priority.slots[0].expiring.Store(true)
		sch.priority.slots[1].degraded.Store(true)
		want := "[0:1:heavy+expiring, 1:0:degraded]"
		if got := statusString(sch.priority); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("respects liveCount bound", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 0}, [2]int32{2, 0}, [2]int32{3, 0})
		sch.priority.slots[2].degraded.Store(true)
		sch.priority.liveCount.Store(2)
		want := "[0:1:active, 1:2:active]"
		if got := statusString(sch.priority); got != want {
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
		if got := statusString(sch.priority); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("both pools render independently from idx 0", func(t *testing.T) {
		sch := newTwoPoolScheduler(
			[][2]int32{{1, 0}, {3, 0}},
			[][2]int32{{2, 0}},
		)
		// Each pool numbers its own slots from 0: the priority pool renders
		// two entries, the bulk pool its own single entry — the bulk slot's
		// real idx is 0 (pool-local), not a global continuation.
		if got, want := statusString(sch.priority), "[0:1:active, 1:3:active]"; got != want {
			t.Fatalf("priority slotStatusString() = %q, want %q", got, want)
		}
		if got, want := statusString(sch.bulk), "[0:2:active]"; got != want {
			t.Fatalf("bulk slotStatusString() = %q, want %q", got, want)
		}
	})
}
