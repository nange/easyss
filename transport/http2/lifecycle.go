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
// samples download throughput for degraded detection, and connection
// rotation once the lifetime or bytes limit is exceeded. It reuses the
// scheduler's pool management to retire idle degraded slots.
type slotLifecycle struct {
	sched        *slotScheduler
	connLifetime time.Duration // max age of a connection before rotation
	connMaxBytes int64         // max bytes per connection before rotation
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

// evaluate walks the live slots: download throughput feeds the degraded
// detector, connection age/bytes feed rotation, and idle degraded slots are
// retired.
func (lc *slotLifecycle) evaluate(interval time.Duration) {
	// A congested link (high RTT) makes every connection slow: marking or
	// retiring slots then only adds handshake churn without recovering
	// anything, so degraded detection is gated on a healthy RTT. Rotation,
	// on the other hand, is exactly what a throttled connection needs and
	// runs regardless of RTT.
	linkOK := stats.Collect().AvgRTT() <= sharedconfig.DegradedMaxRTT

	live := int(lc.sched.liveCount.Load())
	for i := 0; i < live; i++ {
		s := lc.sched.slots[i]
		lc.evaluateSlotHealth(i, s, interval, linkOK)
		lc.evaluateRotation(i, s)
		if linkOK && s.degraded.Load() && s.active.Load() == 0 {
			lc.retire(i, s)
			// retire swap-removes the slot to the end and shrinks
			// liveCount; re-evaluate the slot swapped into position i.
			live--
			i--
		}
	}
}

// evaluateSlotHealth updates one slot's degraded state from its recent
// download throughput. Only slots hosting heavy streams are considered —
// idle or short-lived slots naturally carry zero throughput. The mark is
// set after DegradedPersistCycles consecutive slow intervals and cleared
// after DegradedRecoverCycles healthy ones.
func (lc *slotLifecycle) evaluateSlotHealth(idx int, s *transportSlot, interval time.Duration, linkOK bool) {
	if s.heavy.Load() == 0 {
		s.lastHeavy = 0
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
		s.degraded.Store(true)
		s.lowCycles = 0
		stats.RecordSlotDegraded()
		log.Info("[TRANSPORT] slot degraded", "slot", idx, "throughput_kb_s", throughput/1024)
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
// or bytes limit and should stop accepting new streams.
func (lc *slotLifecycle) rotationDue(s *transportSlot, now time.Time) bool {
	if lc.connLifetime > 0 {
		if expireAt := s.expireAt.Load(); expireAt > 0 && now.UnixNano() >= expireAt {
			return true
		}
	}
	if lc.connMaxBytes > 0 && s.connBytesRecv.Load() >= lc.connMaxBytes {
		return true
	}
	return false
}

// rotationLifetime returns the connection lifetime with a per-connection
// random jitter of up to 20%. Connections created in the same burst (e.g.
// several slots dialing together) then expire in different health ticks,
// so rotations and the subsequent TLS handshakes do not cluster into a
// single fingerprintable burst.
func rotationLifetime(base time.Duration) time.Duration {
	span := int64(base) / 5
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
