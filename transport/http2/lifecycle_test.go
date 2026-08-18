package http2

import (
	"net/http"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
)

func TestEvaluateSlotHealth(t *testing.T) {
	interval := sharedconfig.HealthCheckInterval
	lc := &slotLifecycle{}

	newHeavySlot := func() *transportSlot {
		s := &transportSlot{t: &http.Transport{}}
		s.heavy.Store(1)
		return s
	}
	// lowThroughput simulates one health interval carrying 10KB
	// (2KB/s, well below the 64KB/s degraded threshold).
	lowThroughput := func(s *transportSlot) {
		s.bytesRecv.Add(10 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
	}
	highThroughput := func(s *transportSlot) {
		s.bytesRecv.Add(2 * 1024 * 1024) // 2MB over 5s = 400KB/s
		lc.evaluateSlotHealth(0, s, interval, true)
	}

	t.Run("marks degraded after consecutive slow intervals", func(t *testing.T) {
		s := newHeavySlot()
		// The first interval after heavy 0->1 only resets the throughput
		// baseline and is skipped.
		lowThroughput(s)
		for i := 0; i < sharedconfig.DegradedPersistCycles-1; i++ {
			lowThroughput(s)
			if s.degraded.Load() {
				t.Fatalf("degraded too early at cycle %d", i+1)
			}
		}
		lowThroughput(s)
		if !s.degraded.Load() {
			t.Fatal("expected degraded after persist cycles")
		}
	})

	t.Run("healthy interval resets the slow counter", func(t *testing.T) {
		s := newHeavySlot()
		lowThroughput(s) // baseline reset
		lowThroughput(s)
		lowThroughput(s)
		highThroughput(s)
		lowThroughput(s)
		lowThroughput(s)
		if s.degraded.Load() {
			t.Fatal("expected not degraded after a healthy interval")
		}
	})

	t.Run("clears degraded after consecutive healthy intervals", func(t *testing.T) {
		s := newHeavySlot()
		lowThroughput(s) // baseline reset
		for i := 0; i < sharedconfig.DegradedPersistCycles; i++ {
			lowThroughput(s)
		}
		if !s.degraded.Load() {
			t.Fatal("expected degraded")
		}
		highThroughput(s)
		if !s.degraded.Load() {
			t.Fatal("cleared too early after a single healthy interval")
		}
		highThroughput(s)
		if s.degraded.Load() {
			t.Fatal("expected cleared after recover cycles")
		}
	})

	t.Run("slots without heavy streams never degrade", func(t *testing.T) {
		s := &transportSlot{t: &http.Transport{}}
		for i := 0; i < sharedconfig.DegradedPersistCycles+2; i++ {
			lowThroughput(s)
		}
		if s.degraded.Load() {
			t.Fatal("non-heavy slot must not degrade")
		}
	})

	t.Run("congested link never degrades", func(t *testing.T) {
		s := newHeavySlot()
		// Baseline reset happens before the congestion gate.
		lc.evaluateSlotHealth(0, s, interval, false)
		for i := 0; i < sharedconfig.DegradedPersistCycles+2; i++ {
			s.bytesRecv.Add(10 * 1024)
			lc.evaluateSlotHealth(0, s, interval, false)
		}
		if s.degraded.Load() {
			t.Fatal("degraded while link congested")
		}
	})

	t.Run("heavy 0->1 transition resets throughput baseline", func(t *testing.T) {
		s := newHeavySlot()
		s.bytesRecv.Add(50 * 1024) // stale bytes from earlier small streams
		// First sample only resets the baseline.
		lc.evaluateSlotHealth(0, s, interval, true)
		if s.lowCycles != 0 {
			t.Fatalf("lowCycles = %d after baseline reset, want 0", s.lowCycles)
		}
		// A slow interval afterwards counts from the reset point.
		s.bytesRecv.Add(10 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
		if s.lowCycles != 1 {
			t.Fatalf("lowCycles = %d, want 1", s.lowCycles)
		}
	})
}

func TestRotationDue(t *testing.T) {
	now := time.Now()
	t.Run("lifetime exceeded", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Minute}
		s := &transportSlot{}
		s.expireAt.Store(now.Add(-2 * time.Minute).UnixNano())
		if !lc.rotationDue(s, now) {
			t.Fatal("expected rotation due by age")
		}
	})

	t.Run("bytes exceeded", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Hour, connMaxBytes: 1024}
		s := &transportSlot{}
		s.expireAt.Store(now.Add(time.Hour).UnixNano())
		s.connBytesRecv.Store(2048)
		if !lc.rotationDue(s, now) {
			t.Fatal("expected rotation due by bytes")
		}
	})

	t.Run("fresh connection not due", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Minute, connMaxBytes: 1024}
		s := &transportSlot{}
		s.expireAt.Store(now.Add(time.Minute).UnixNano())
		s.connBytesRecv.Store(512)
		if lc.rotationDue(s, now) {
			t.Fatal("fresh connection must not rotate")
		}
	})

	t.Run("never dialed slot not due by age", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Minute}
		s := &transportSlot{}
		if lc.rotationDue(s, now) {
			t.Fatal("undialed slot must not rotate")
		}
	})
}

func TestRotationLifetimeJitter(t *testing.T) {
	const base = 15 * time.Minute
	max := base + base/5
	for i := 0; i < 1000; i++ {
		got := rotationLifetime(base)
		if got < base || got > max {
			t.Fatalf("rotationLifetime(%v) = %v, want within [%v, %v]", base, got, base, max)
		}
	}
}

func TestEvaluateRotation(t *testing.T) {
	t.Run("marks expiring and completes rotation when idle", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Minute}
		s := &transportSlot{t: &http.Transport{}}
		s.expireAt.Store(time.Now().Add(-2 * time.Minute).UnixNano())
		s.active.Store(1)
		// First pass: still busy, only mark expiring.
		lc.evaluateRotation(0, s)
		if !s.expiring.Load() {
			t.Fatal("expected expiring mark")
		}
		// Second pass: idle now, rotation completes and clears the mark.
		s.active.Store(0)
		lc.evaluateRotation(0, s)
		if s.expiring.Load() {
			t.Fatal("expected expiring cleared after rotation")
		}
	})

	t.Run("fresh connection not expiring", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Hour}
		s := &transportSlot{t: &http.Transport{}}
		s.expireAt.Store(time.Now().Add(time.Hour).UnixNano())
		lc.evaluateRotation(0, s)
		if s.expiring.Load() {
			t.Fatal("fresh connection must not expire")
		}
	})
}
