package http2

import (
	"context"
	"math/rand/v2"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// slotLifecycle owns the per-slot connection lifecycle: a health loop that
// samples download throughput for degradation suspicion and confirms it with
// an active probe over the slot's own connection, plus connection rotation
// once the lifetime or bytes limit is exceeded. It reuses the scheduler's
// pool management to retire idle degraded slots.
type slotLifecycle struct {
	sched        *slotScheduler
	connLifetime time.Duration // max age of a connection before rotation
	connMaxBytes int64         // max bytes per connection before rotation

	// probeFunc actively measures one slot's connection throughput; nil
	// disables probing (no probe token configured).
	probeFunc func(ctx context.Context, slot *transportSlot) (speedBps float64, verdict probeVerdict)

	// Probe state, touched only from the health loop goroutine.
	probeUnsupported bool    // server does not serve /v3/probe: fall back to passive-only detection
	unsupportedCount int     // unsupported probe verdicts seen
	linkRefSpeed     float64 // best probe speed observed on this link recently (bytes/s)
	linkRefAt        time.Time
}

// run drives the periodic health evaluation until ctx is cancelled.
func (lc *slotLifecycle) run(ctx context.Context) {
	interval := sharedconfig.HealthCheckInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			lc.evaluate(interval)
		case <-ctx.Done():
			return
		}
	}
}

// evaluate walks the live slots of both pools: download throughput feeds
// the degradation suspicion detector, active probes confirm suspicions,
// connection age/bytes feed rotation, and idle degraded slots are retired.
func (lc *slotLifecycle) evaluate(interval time.Duration) {
	// A congested link (high RTT) makes every connection slow: marking or
	// retiring slots then only adds handshake churn without recovering
	// anything, so degraded detection is gated on a healthy RTT. Rotation,
	// on the other hand, is exactly what a throttled connection needs and
	// runs regardless of RTT.
	linkOK := stats.Collect().AvgRTT() <= sharedconfig.DegradedMaxRTT

	for _, pool := range []*slotPool{lc.sched.priority, lc.sched.bulk} {
		// Snapshot the live slots under the scheduler read lock: shrink and
		// retire swap-remove slots under the write lock, so iterating the
		// live range unlocked would race with those swaps.
		lc.sched.mu.RLock()
		live := int(pool.liveCount.Load())
		slots := make([]*transportSlot, live)
		copy(slots, pool.slots[:live])
		lc.sched.mu.RUnlock()

		for i, s := range slots {
			lc.evaluateSlotHealth(i, s, interval, linkOK)
			lc.evaluateRotation(i, s)
			if linkOK && s.degraded.Load() && s.active.Load() == 0 {
				lc.retire(i, s)
			}
		}
	}

	lc.evaluateProbes(linkOK)
}

// evaluateSlotHealth updates one slot's suspicion from its recent download
// throughput. Only slots hosting heavy streams are considered — idle or
// short-lived slots naturally carry zero throughput. When probing is active
// (server serves /v3/probe), persistent low throughput only marks the slot
// as suspected and an active probe confirms or refutes it; without probing
// (server does not support it, or no probe token configured), the suspicion
// directly marks the slot degraded (legacy behavior). The mark is cleared
// after DegradedRecoverCycles healthy intervals in both modes.
func (lc *slotLifecycle) evaluateSlotHealth(idx int, s *transportSlot, interval time.Duration, linkOK bool) {
	if s.heavy.Load() == 0 {
		s.lastHeavy = 0
		s.suspected = false
		return
	}
	if s.lastHeavy == 0 {
		// First heavy stream on this slot since it went idle: bytes
		// transferred by earlier small streams must not skew the first
		// sample, so reset the baseline and skip this interval.
		s.lastHeavy = 1
		s.lastBytes = s.bytesRecv.Load()
		s.lowCycles = 0
		s.recoverCycles = 0
		return
	}
	if !linkOK {
		// Congested link: low throughput is a link property, not evidence
		// that this particular connection is broken. Advance the baseline
		// so the first healthy interval starts from a clean sample, and
		// freeze the counters.
		s.lastBytes = s.bytesRecv.Load()
		return
	}

	now := s.bytesRecv.Load()
	perSec := int64(interval / time.Second)
	if perSec <= 0 {
		perSec = 1
	}
	throughput := (now - s.lastBytes) / perSec
	s.lastBytes = now

	if throughput >= int64(sharedconfig.DegradedThroughputThreshold) {
		s.lowCycles = 0
		s.suspected = false
		if s.degraded.Load() {
			s.recoverCycles++
			if s.recoverCycles >= sharedconfig.DegradedRecoverCycles {
				s.degraded.Store(false)
				s.recoverCycles = 0
				log.Info("[TRANSPORT] slot recovered", "slot", idx, "throughput_kb_s", throughput/1024)
			}
		}
		return
	}

	s.recoverCycles = 0
	s.lowCycles++
	if s.lowCycles >= sharedconfig.DegradedPersistCycles && !s.degraded.Load() {
		s.lowCycles = 0
		if lc.probeUnsupported || lc.probeFunc == nil {
			// No active probing (server does not serve /v3/probe, or no
			// probe token configured): the passive sampler marks the slot
			// degraded directly, as before probing existed.
			s.degraded.Store(true)
			stats.RecordSlotDegraded()
			log.Info("[TRANSPORT] slot degraded", "slot", idx, "throughput_kb_s", throughput/1024)
		} else {
			s.suspected = true
		}
	}
}

// evaluateProbes confirms degradation suspicions with active probes. Only
// slots suspected by the passive sampler are probed, and only while the link
// RTT is healthy (a congested link makes every probe slow). Each tick probes
// at most ProbeMaxPerInterval slots; a slot is re-probed at most once per
// ProbeCooldown.
func (lc *slotLifecycle) evaluateProbes(linkOK bool) {
	if !linkOK || lc.probeUnsupported || lc.probeFunc == nil {
		return
	}

	now := time.Now()
	probed := 0
	for _, pool := range []*slotPool{lc.sched.priority, lc.sched.bulk} {
		// Same snapshot discipline as evaluate: the live range may be
		// swap-mutated by shrink/retire under the write lock.
		lc.sched.mu.RLock()
		live := int(pool.liveCount.Load())
		slots := make([]*transportSlot, live)
		copy(slots, pool.slots[:live])
		lc.sched.mu.RUnlock()

		for i := 0; i < len(slots) && probed < sharedconfig.ProbeMaxPerInterval; i++ {
			s := slots[i]
			if !s.suspected || s.degraded.Load() {
				continue
			}
			if now.Sub(s.lastProbeAt) < sharedconfig.ProbeCooldown {
				continue
			}
			lc.probeSlot(i, s, now)
			probed++
		}
	}
}

// probeSlot runs one probe and folds its verdict into the slot's degraded
// state:
//   - slow: confirmed after ProbeConfirmCycles consecutive slow probes —
//     unless the link reference speed shows the whole link is the
//     bottleneck, in which case the slot is not to blame;
//   - fast: the connection is healthy (slow traffic is an origin or stream
//     property, not a connection property); clears suspicion;
//   - inconclusive: no state change;
//   - unsupported: after two such verdicts the server is treated as not
//     serving the probe endpoint and detection falls back to passive-only.
func (lc *slotLifecycle) probeSlot(idx int, s *transportSlot, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), sharedconfig.ProbeTimeout)
	defer cancel()

	speed, verdict := lc.probeFunc(ctx, s)
	s.lastProbeAt = now
	stats.RecordSlotProbe()

	switch verdict {
	case probeFast:
		s.probeLowCycles = 0
		s.suspected = false
		// The link reference is the best throughput this link achieved
		// recently; it only refreshes from fast probes.
		if speed > lc.linkRefSpeed || now.Sub(lc.linkRefAt) > sharedconfig.ProbeLinkRefWindow {
			lc.linkRefSpeed = speed
			lc.linkRefAt = now
		}
	case probeSlow:
		// A fresh link reference below the degraded threshold means the
		// whole link is the bottleneck right now: every connection is
		// slow, so blaming this slot would only add handshake churn.
		if now.Sub(lc.linkRefAt) <= sharedconfig.ProbeLinkRefWindow &&
			lc.linkRefSpeed < float64(sharedconfig.DegradedThroughputThreshold) {
			s.probeLowCycles = 0
			s.suspected = false
			return
		}
		stats.RecordSlotProbeSlow()
		s.probeLowCycles++
		if s.probeLowCycles >= sharedconfig.ProbeConfirmCycles {
			s.probeLowCycles = 0
			s.suspected = false
			s.degraded.Store(true)
			stats.RecordSlotDegraded()
			log.Info("[TRANSPORT] slot degraded", "slot", idx, "probe_kb_s", int64(speed)/1024)
		}
	case probeUnsupported:
		lc.unsupportedCount++
		if lc.unsupportedCount >= 2 {
			lc.probeUnsupported = true
			stats.RecordSlotProbeUnsupported()
			log.Info("[TRANSPORT] server does not serve /v3/probe, falling back to passive detection")
		}
	case probeInconclusive:
		// Dead connection (stream errors and rotation handle it) or
		// transient rejection (429): keep the current state, re-probe
		// once the cooldown elapses.
	}
}

// evaluateRotation marks a slot expiring once its connection exceeded the
// lifetime or bytes limit, and completes the rotation once the slot goes
// idle: the tired connection is closed so the next stream dials a fresh
// one. In-flight streams are never interrupted.
func (lc *slotLifecycle) evaluateRotation(idx int, s *transportSlot) {
	if s.expiring.Load() {
		if s.active.Load() == 0 {
			s.t.CloseIdleConnections()
			s.expiring.Store(false)
			stats.RecordConnRotated()
			log.Info("[TRANSPORT] connection rotated", "slot", idx)
		}
		return
	}
	if lc.rotationDue(s, time.Now()) {
		s.expiring.Store(true)
		log.Info("[TRANSPORT] slot connection expiring", "slot", idx)
	}
}

// rotationDue reports whether the slot's connection exceeded the lifetime
// or bytes limit and should stop accepting new streams. The byte limit
// counts traffic in both directions.
func (lc *slotLifecycle) rotationDue(s *transportSlot, now time.Time) bool {
	if lc.connLifetime > 0 {
		if expireAt := s.expireAt.Load(); expireAt > 0 && now.UnixNano() >= expireAt {
			return true
		}
	}
	if lc.connMaxBytes > 0 && s.connBytes.Load() >= lc.connMaxBytes {
		return true
	}
	return false
}

// rotationLifetime returns the connection lifetime with a per-connection
// random jitter of up to 50%. Connections created in the same burst (e.g.
// several slots dialing together) then expire in different health ticks,
// so rotations and the subsequent TLS handshakes do not cluster into a
// single fingerprintable burst. With the default 7-minute lifetime the
// jitter spreads a same-batch expiry over a 3.5-minute window (roughly 42
// health ticks), so a batch never tips into expiring at once and the
// scheduler keeps healthy slots to spread new streams onto.
func rotationLifetime(base time.Duration) time.Duration {
	span := int64(base) / 2
	if span <= 0 {
		return base
	}
	return base + time.Duration(rand.Int64N(span+1))
}

// retire closes a degraded slot's idle connection and removes the slot from
// the live set once it no longer hosts any stream.
func (lc *slotLifecycle) retire(idx int, s *transportSlot) {
	s.t.CloseIdleConnections()
	if !lc.sched.remove(s) {
		return
	}
	stats.RecordSlotRetiredDegraded()
	log.Info("[TRANSPORT] slot retired (degraded)", "slot", idx)
}
