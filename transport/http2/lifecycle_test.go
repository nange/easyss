package http2

import (
	"context"
	"net/http"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
)

func TestEvaluateSlotHealth(t *testing.T) {
	interval := sharedconfig.HealthCheckInterval
	// Legacy mode (probeUnsupported): the passive sampler marks slots
	// degraded directly, as before probing existed.
	lc := &slotLifecycle{probeUnsupported: true}

	newHeavySlot := func() *transportSlot {
		s := &transportSlot{t: &http.Transport{}}
		s.heavy.Store(1)
		return s
	}
	// lowThroughput simulates one health interval carrying 10KB
	// (2KB/s, well below the degraded throughput threshold).
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

// newTestLifecycle builds a lifecycle over n live slots with the given
// probe function (nil disables probing). All n slots live in the priority
// pool (bulk pool stays empty), so tests address them as priority.slots[i].
func newTestLifecycle(n int, probe func(context.Context, *transportSlot) (float64, probeVerdict)) (*slotLifecycle, *slotScheduler) {
	slots := make([]*transportSlot, n)
	for i := range slots {
		slots[i] = &transportSlot{t: &http.Transport{}}
	}
	sch := &slotScheduler{
		priority: &slotPool{
			slots:    slots,
			maxSlots: n,
			base:     8,
		},
		bulk: &slotPool{
			slots:    []*transportSlot{{t: &http.Transport{}}},
			maxSlots: 1,
			base:     16,
		},
		threshold:     8,
		bulkThreshold: 16,
	}
	sch.priority.liveCount.Store(int32(n))
	lc := &slotLifecycle{sched: sch, probeFunc: probe}
	return lc, sch
}

func TestSuspicionInsteadOfDirectMark(t *testing.T) {
	interval := sharedconfig.HealthCheckInterval
	// Probe mode: a probe function is configured, so low passive
	// throughput only raises suspicion; the degraded mark is confirmed by
	// probes. (The fake is never called here — only the passive sampler
	// runs.)
	lc := &slotLifecycle{probeFunc: func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 0, probeInconclusive
	}}
	s := &transportSlot{t: &http.Transport{}}
	s.heavy.Store(1)

	low := func() {
		s.bytesRecv.Add(10 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
	}
	high := func() {
		s.bytesRecv.Add(2 * 1024 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
	}

	low() // baseline reset
	for i := 0; i < sharedconfig.DegradedPersistCycles; i++ {
		low()
	}
	if s.degraded.Load() {
		t.Fatal("probe mode must not mark degraded directly")
	}
	if !s.suspected {
		t.Fatal("expected suspicion after persistent low throughput")
	}

	// A healthy interval clears the suspicion without any probe.
	high()
	if s.suspected {
		t.Fatal("expected suspicion cleared by healthy throughput")
	}
}

func TestNoProbeFuncFallsBackToPassive(t *testing.T) {
	interval := sharedconfig.HealthCheckInterval
	// No probe function configured (e.g. no probe token): the passive
	// sampler keeps its legacy direct marking.
	lc := &slotLifecycle{}
	s := &transportSlot{t: &http.Transport{}}
	s.heavy.Store(1)

	lc.evaluateSlotHealth(0, s, interval, true) // baseline reset
	for i := 0; i < sharedconfig.DegradedPersistCycles; i++ {
		s.bytesRecv.Add(10 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
	}
	if !s.degraded.Load() {
		t.Fatal("expected legacy degraded marking without a probe function")
	}
	if s.suspected {
		t.Fatal("legacy mode must not set suspicion")
	}
}

func TestProbeConfirmDegraded(t *testing.T) {
	lc, sch := newTestLifecycle(2, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 10 * 1024, probeSlow // 10KB/s, well below 64KB/s
	})
	s := sch.priority.slots[0]
	s.suspected = true

	lc.evaluateProbes(true)
	if s.degraded.Load() {
		t.Fatal("degraded after a single slow probe")
	}
	if s.probeLowCycles != 1 {
		t.Fatalf("probeLowCycles = %d, want 1", s.probeLowCycles)
	}

	s.lastProbeAt = time.Time{} // bypass cooldown
	lc.evaluateProbes(true)
	if !s.degraded.Load() {
		t.Fatal("expected degraded after ProbeConfirmCycles slow probes")
	}
	if s.suspected {
		t.Fatal("expected suspicion cleared once degraded")
	}
}

func TestProbeFastClearsSuspicion(t *testing.T) {
	const fastSpeed = 10 * 1024 * 1024 // 10MB/s
	calls := 0
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		calls++
		return fastSpeed, probeFast
	})
	s := sch.priority.slots[0]
	s.suspected = true

	lc.evaluateProbes(true)

	if calls != 1 {
		t.Fatalf("probe calls = %d, want 1", calls)
	}
	if s.suspected {
		t.Fatal("fast probe must clear suspicion")
	}
	if s.degraded.Load() {
		t.Fatal("fast probe must not mark degraded")
	}
	if lc.linkRefSpeed != fastSpeed {
		t.Fatalf("linkRefSpeed = %v, want %v", lc.linkRefSpeed, fastSpeed)
	}
}

func TestProbeSlowRespectsLinkReference(t *testing.T) {
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 30 * 1024, probeSlow
	})
	s := sch.priority.slots[0]

	// A fresh link reference below the degraded threshold means the whole
	// link is the bottleneck: the slow probe must not blame the slot.
	lc.linkRefSpeed = 32 * 1024
	lc.linkRefAt = time.Now()
	s.suspected = true
	lc.evaluateProbes(true)
	if s.degraded.Load() || s.probeLowCycles != 0 || s.suspected {
		t.Fatal("must not mark or keep suspicion while the link itself is slow")
	}

	// A healthy link reference: the slot's connection is to blame.
	lc.linkRefSpeed = 1024 * 1024
	lc.linkRefAt = time.Now()
	s.suspected = true
	s.lastProbeAt = time.Time{}
	lc.evaluateProbes(true)
	s.lastProbeAt = time.Time{}
	lc.evaluateProbes(true)
	if !s.degraded.Load() {
		t.Fatal("expected degraded with a healthy link reference")
	}
}

func TestProbeUnsupportedFallsBackToPassive(t *testing.T) {
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 0, probeUnsupported
	})
	s := sch.priority.slots[0]
	s.suspected = true

	lc.evaluateProbes(true)
	if lc.probeUnsupported {
		t.Fatal("unsupported too early after a single verdict")
	}
	s.lastProbeAt = time.Time{}
	lc.evaluateProbes(true)
	if !lc.probeUnsupported {
		t.Fatal("expected probeUnsupported after two verdicts")
	}

	// The passive sampler now marks degraded directly (legacy behavior).
	interval := sharedconfig.HealthCheckInterval
	s.suspected = false
	s.heavy.Store(1)
	lc.evaluateSlotHealth(0, s, interval, true) // baseline reset
	for i := 0; i < sharedconfig.DegradedPersistCycles; i++ {
		s.bytesRecv.Add(10 * 1024)
		lc.evaluateSlotHealth(0, s, interval, true)
	}
	if !s.degraded.Load() {
		t.Fatal("expected legacy degraded marking after fallback")
	}
}

func TestProbeInconclusiveKeepsState(t *testing.T) {
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		return 0, probeInconclusive
	})
	s := sch.priority.slots[0]
	s.suspected = true

	lc.evaluateProbes(true)

	if !s.suspected {
		t.Fatal("inconclusive probe must keep suspicion")
	}
	if s.probeLowCycles != 0 {
		t.Fatalf("probeLowCycles = %d, want 0", s.probeLowCycles)
	}
	if lc.probeUnsupported {
		t.Fatal("inconclusive must not count as unsupported")
	}
}

func TestProbeCooldown(t *testing.T) {
	calls := 0
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		calls++
		return 10 * 1024, probeSlow
	})
	s := sch.priority.slots[0]
	s.suspected = true
	s.lastProbeAt = time.Now() // probed moments ago

	lc.evaluateProbes(true)

	if calls != 0 {
		t.Fatal("probe must be skipped within the cooldown")
	}
}

func TestProbeMaxPerInterval(t *testing.T) {
	calls := 0
	lc, sch := newTestLifecycle(3, func(context.Context, *transportSlot) (float64, probeVerdict) {
		calls++
		return 10 * 1024, probeSlow
	})
	for i := 0; i < 3; i++ {
		sch.priority.slots[i].suspected = true
	}

	lc.evaluateProbes(true)

	if calls != sharedconfig.ProbeMaxPerInterval {
		t.Fatalf("probe calls = %d, want %d", calls, sharedconfig.ProbeMaxPerInterval)
	}
	if sch.priority.slots[2].probeLowCycles != 0 {
		t.Fatal("the third suspect must wait for the next tick")
	}
}

func TestProbesPausedOnCongestedLink(t *testing.T) {
	calls := 0
	lc, sch := newTestLifecycle(1, func(context.Context, *transportSlot) (float64, probeVerdict) {
		calls++
		return 10 * 1024, probeSlow
	})
	sch.priority.slots[0].suspected = true

	lc.evaluateProbes(false)

	if calls != 0 {
		t.Fatal("no probes while the link is congested")
	}
}

func TestProbesDisabledWithoutProbeFunc(t *testing.T) {
	lc, sch := newTestLifecycle(1, nil)
	sch.priority.slots[0].suspected = true

	lc.evaluateProbes(true)

	if sch.priority.slots[0].probeLowCycles != 0 {
		t.Fatal("no probing without a probe function")
	}
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
		s.connBytes.Store(2048)
		if !lc.rotationDue(s, now) {
			t.Fatal("expected rotation due by bytes")
		}
	})

	t.Run("fresh connection not due", func(t *testing.T) {
		lc := &slotLifecycle{connLifetime: time.Minute, connMaxBytes: 1024}
		s := &transportSlot{}
		s.expireAt.Store(now.Add(time.Minute).UnixNano())
		s.connBytes.Store(512)
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
	max := base + base/2
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
		s.connBytes.Store(1024)
		s.active.Store(1)
		// First pass: still busy, only mark expiring.
		lc.evaluateRotation(0, s)
		if !s.expiring.Load() {
			t.Fatal("expected expiring mark")
		}
		// Second pass: idle now, rotation completes and clears the mark.
		// The deadline and bytes are zeroed too, so the completed rotation
		// cannot re-trigger on the recycled connection's state.
		s.active.Store(0)
		lc.evaluateRotation(0, s)
		if s.expiring.Load() {
			t.Fatal("expected expiring cleared after rotation")
		}
		if s.expireAt.Load() != 0 {
			t.Fatalf("expireAt = %d, want 0 after rotation completed", s.expireAt.Load())
		}
		if s.connBytes.Load() != 0 {
			t.Fatalf("connBytes = %d, want 0 after rotation completed", s.connBytes.Load())
		}
		// Third pass: the slot has no connection anymore, so it must not
		// be marked expiring again on every tick.
		lc.evaluateRotation(0, s)
		if s.expiring.Load() {
			t.Fatal("expected no expiring mark after rotation completed")
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

func TestResetRotationClearsMarks(t *testing.T) {
	s := &transportSlot{}
	// A slot revived by grow (or after a completed rotation) carries the
	// previous connection's state: an overdue deadline, bytes carried and
	// expiring/degraded verdicts. resetRotation must return it to the "no
	// connection" baseline: no marks, zero deadline, zero bytes — so
	// rotationDue never triggers on the recycled connection's state.
	s.degraded.Store(true)
	s.expiring.Store(true)
	s.expireAt.Store(time.Now().Add(-time.Minute).UnixNano())
	s.connBytes.Store(1024)

	s.resetRotation()

	if s.degraded.Load() {
		t.Fatal("expected degraded cleared")
	}
	if s.expiring.Load() {
		t.Fatal("expected expiring cleared")
	}
	if s.connBytes.Load() != 0 {
		t.Fatalf("connBytes = %d, want 0", s.connBytes.Load())
	}
	if s.expireAt.Load() != 0 {
		t.Fatalf("expireAt = %d, want 0 (no connection yet)", s.expireAt.Load())
	}
	// A slot without a connection must never be judged overdue.
	lc := &slotLifecycle{connLifetime: time.Minute}
	if lc.rotationDue(s, time.Now()) {
		t.Fatal("slot without a connection must not be due for rotation")
	}
}

func TestResetConnClearsMarks(t *testing.T) {
	s := &transportSlot{}
	// A retiring slot (degraded+expiring) past its lifetime with bytes
	// carried: after a fresh connection is established, the rotation state
	// starts over and the degraded verdict of the old connection is void.
	s.degraded.Store(true)
	s.expiring.Store(true)
	s.expireAt.Store(time.Now().Add(-time.Minute).UnixNano())
	s.connBytes.Store(1024)

	s.resetConn(time.Hour)

	if s.degraded.Load() {
		t.Fatal("expected degraded cleared on a fresh connection")
	}
	if s.expiring.Load() {
		t.Fatal("expected expiring cleared on a fresh connection")
	}
	if s.connBytes.Load() != 0 {
		t.Fatalf("connBytes = %d, want 0", s.connBytes.Load())
	}
	if expireAt := s.expireAt.Load(); expireAt <= time.Now().UnixNano() {
		t.Fatalf("expireAt = %d, want a future deadline", expireAt)
	}
}
