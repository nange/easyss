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

func TestSlotStatusString(t *testing.T) {
	t.Run("empty live set", func(t *testing.T) {
		sch := newTestScheduler()
		if got := slotStatusString(sch, int(sch.liveCount.Load())); got != "[]" {
			t.Fatalf("slotStatusString() = %q, want %q", got, "[]")
		}
	})

	t.Run("all active with stream counts", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 0}, [2]int32{2, 0})
		if got, want := slotStatusString(sch, int(sch.liveCount.Load())), "[0:1:active, 1:2:active]"; got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("mixed states", func(t *testing.T) {
		sch := newTestScheduler([2]int32{3, 0}, [2]int32{2, 0}, [2]int32{1, 0}, [2]int32{1, 1})
		sch.slots[0].degraded.Store(true)
		sch.slots[1].expiring.Store(true)
		want := "[0:3:degraded, 1:2:expiring, 2:1:active, 3:1:heavy]"
		if got := slotStatusString(sch, int(sch.liveCount.Load())); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("combined flags", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 1}, [2]int32{0, 0})
		sch.slots[0].expiring.Store(true)
		sch.slots[1].degraded.Store(true)
		want := "[0:1:heavy+expiring, 1:0:degraded]"
		if got := slotStatusString(sch, int(sch.liveCount.Load())); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("respects liveCount bound", func(t *testing.T) {
		sch := newTestScheduler([2]int32{1, 0}, [2]int32{2, 0}, [2]int32{3, 0})
		sch.slots[2].degraded.Store(true)
		sch.liveCount.Store(2)
		want := "[0:1:active, 1:2:active]"
		if got := slotStatusString(sch, int(sch.liveCount.Load())); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})

	t.Run("scrambled live order is renumbered consecutively", func(t *testing.T) {
		// Simulate a swap-remove of slot 1: positions [0,1,2] now hold
		// slots with real indices 0,3,2 and liveCount dropped to 3. Entries
		// stay ordered by real index but are renumbered 0..n-1, so the
		// output indices never jump.
		sch := newTestScheduler([2]int32{1, 0}, [2]int32{2, 0}, [2]int32{3, 0}, [2]int32{4, 0})
		sch.slots[1], sch.slots[3] = sch.slots[3], sch.slots[1]
		sch.liveCount.Store(3)
		want := "[0:1:active, 1:3:active, 2:4:active]"
		if got := slotStatusString(sch, int(sch.liveCount.Load())); got != want {
			t.Fatalf("slotStatusString() = %q, want %q", got, want)
		}
	})
}
