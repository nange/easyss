package http2

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/transport"
)

func TestUTLSDialUsesHTTP2(t *testing.T) {
	protoCh := make(chan string, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protoCh <- r.Proto
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	slot := newSlot(&utls.Config{
		InsecureSkipVerify: true,
		NextProtos:         sharedconfig.NextProtos,
	}, time.Second, nil, time.Minute)
	t.Cleanup(slot.t.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodPost, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := slot.t.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if got := <-protoCh; got != "HTTP/2.0" {
		t.Fatalf("server got %s, want HTTP/2.0", got)
	}
}

// TestHTTP2Transport_Non200StatusIsRejected verifies that a handshake
// answered with a non-200 status (e.g. 408 Request Timeout) fails fast with a
// HandshakeRejectedError instead of exposing the rejection body to the record
// reader.
func TestHTTP2Transport_Non200StatusIsRejected(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusRequestTimeout)
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tr, err := New(Config{
		ServerURL: srv.URL,
		TLSConfig: &utls.Config{
			InsecureSkipVerify: true,
			NextProtos:         sharedconfig.NextProtos,
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	stream, err := tr.Open(context.Background(), transport.OpenRequest{
		Endpoint:     sharedconfig.EndpointTCP,
		Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
		HighPriority: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close() //nolint:errcheck

	buf := make([]byte, 16)
	_, err = stream.Read(buf)
	if err == nil {
		t.Fatal("expected a rejection error, got nil")
	}
	if !transport.IsHandshakeRejected(err) {
		t.Fatalf("expected HandshakeRejectedError, got: %v", err)
	}
}

// TestHTTP2Transport_200StatusReadsBody verifies that a 200 response is
// surfaced as a normal readable body.
func TestHTTP2Transport_200StatusReadsBody(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tr, err := New(Config{
		ServerURL: srv.URL,
		TLSConfig: &utls.Config{
			InsecureSkipVerify: true,
			NextProtos:         sharedconfig.NextProtos,
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	stream, err := tr.Open(context.Background(), transport.OpenRequest{
		Endpoint:     sharedconfig.EndpointTCP,
		Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
		HighPriority: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close() //nolint:errcheck

	body, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Fatalf("got %q, want %q", body, "hello")
	}
}

// newTestSlots builds live slots with explicit active/heavy counters.
// Transport structs inside slots are left nil — scheduling tests never dial.
func newTestSlots(specs ...[2]int32) *HTTP2Transport {
	slots := make([]*transportSlot, len(specs))
	for i, s := range specs {
		slots[i] = &transportSlot{}
		slots[i].active.Store(s[0])
		slots[i].heavy.Store(s[1])
	}
	tr := &HTTP2Transport{
		slots:    slots,
		maxSlots: len(slots),
	}
	tr.liveCount.Store(int32(len(slots)))
	return tr
}

func TestLeastActiveSlotRangeSkipsHeavy(t *testing.T) {
	t.Run("prefers non-heavy slot", func(t *testing.T) {
		tr := newTestSlots([2]int32{5, 1}, [2]int32{2, 0})
		if got := tr.leastActiveSlotRange(0, 2); got != tr.slots[1] {
			t.Fatalf("expected non-heavy slot 1, got active=%d heavy=%d", got.active.Load(), got.heavy.Load())
		}
	})

	t.Run("picks least active among non-heavy", func(t *testing.T) {
		tr := newTestSlots([2]int32{5, 0}, [2]int32{2, 1}, [2]int32{3, 0})
		if got := tr.leastActiveSlotRange(0, 3); got != tr.slots[2] {
			t.Fatalf("expected least-active non-heavy slot 2, got active=%d heavy=%d", got.active.Load(), got.heavy.Load())
		}
	})

	t.Run("falls back to least active when all heavy", func(t *testing.T) {
		tr := newTestSlots([2]int32{5, 1}, [2]int32{2, 1})
		if got := tr.leastActiveSlotRange(0, 2); got != tr.slots[1] {
			t.Fatalf("expected least-active slot 1, got active=%d heavy=%d", got.active.Load(), got.heavy.Load())
		}
	})

	t.Run("respects liveCount bound", func(t *testing.T) {
		tr := newTestSlots([2]int32{5, 0}, [2]int32{2, 0}, [2]int32{3, 0})
		tr.liveCount.Store(2)
		if got := tr.leastActiveSlotRange(0, 3); got != tr.slots[1] {
			t.Fatalf("expected slot 1 within live range, got active=%d", got.active.Load())
		}
	})
}

func TestTrackReadMarksSlotHeavy(t *testing.T) {
	// Fast path: a large transfer is marked as soon as it crosses the
	// cumulative size threshold.
	t.Run("fast large transfer marks at size threshold", func(t *testing.T) {
		slot := &transportSlot{}
		stream := &HTTP2Stream{slot: slot, startTime: time.Now()}

		// Below the fast threshold and too young for the slow path: no mark.
		stream.trackRead(sharedconfig.HeavyStreamThresholdBytes - 1)
		if slot.heavy.Load() != 0 || stream.heavyState.Load() != heavyIdle {
			t.Fatalf("marked heavy before threshold: slot.heavy=%d state=%d", slot.heavy.Load(), stream.heavyState.Load())
		}

		// Crossing the fast threshold: mark exactly once.
		stream.trackRead(2)
		if slot.heavy.Load() != 1 || stream.heavyState.Load() != heavyMarked {
			t.Fatalf("expected heavy mark after threshold: slot.heavy=%d state=%d", slot.heavy.Load(), stream.heavyState.Load())
		}
		if slot.bytesRecv.Load() != int64(sharedconfig.HeavyStreamThresholdBytes+1) {
			t.Fatalf("bytesRecv not accumulated: %d", slot.bytesRecv.Load())
		}
		if slot.connBytesRecv.Load() != slot.bytesRecv.Load() {
			t.Fatalf("connBytesRecv = %d, want %d", slot.connBytesRecv.Load(), slot.bytesRecv.Load())
		}

		// Further transfers must not double-mark.
		stream.trackRead(64 * 1024)
		if slot.heavy.Load() != 1 {
			t.Fatalf("heavy marked more than once: %d", slot.heavy.Load())
		}

		// Release on stream end: mirrors the doneOnce logic in Open.
		stream.releaseHeavy()
		if slot.heavy.Load() != 0 {
			t.Fatalf("heavy mark not released: %d", slot.heavy.Load())
		}
		if stream.heavyState.Load() != heavyReleased {
			t.Fatalf("state = %d, want released", stream.heavyState.Load())
		}
	})

	// Slow path: on a poor link even a sub-MB transfer becomes long-lived,
	// so it must be marked once the stream has been alive long enough.
	t.Run("slow transfer marks after min age", func(t *testing.T) {
		slot := &transportSlot{}
		stream := &HTTP2Stream{
			slot:      slot,
			startTime: time.Now().Add(-sharedconfig.HeavyStreamMinAge - time.Second),
		}

		// Below the slow threshold: no mark regardless of age.
		stream.trackRead(sharedconfig.HeavyStreamSlowThresholdBytes - 1)
		if slot.heavy.Load() != 0 {
			t.Fatalf("marked heavy below slow threshold: %d", slot.heavy.Load())
		}

		// At or above the slow threshold with sufficient age: mark once.
		stream.trackRead(1024)
		if slot.heavy.Load() != 1 || stream.heavyState.Load() != heavyMarked {
			t.Fatalf("expected heavy mark on slow path: slot.heavy=%d state=%d", slot.heavy.Load(), stream.heavyState.Load())
		}
	})

	// A young stream below the fast threshold must not be marked.
	t.Run("young stream below fast threshold not marked", func(t *testing.T) {
		slot := &transportSlot{}
		stream := &HTTP2Stream{slot: slot, startTime: time.Now()}

		stream.trackRead(sharedconfig.HeavyStreamSlowThresholdBytes)
		if slot.heavy.Load() != 0 {
			t.Fatalf("young stream marked heavy: %d", slot.heavy.Load())
		}
	})

	// Nil slot is a no-op (e.g. test-constructed streams).
	t.Run("nil slot no-op", func(t *testing.T) {
		noSlot := &HTTP2Stream{}
		noSlot.trackRead(sharedconfig.HeavyStreamThresholdBytes)
		if noSlot.heavyState.Load() != heavyIdle {
			t.Fatal("nil slot must not be marked heavy")
		}
	})

	// Releasing before the stream ever qualified as heavy must never
	// increment the slot counter, and a later transfer must not leak it.
	t.Run("release before marking never increments", func(t *testing.T) {
		slot := &transportSlot{}
		stream := &HTTP2Stream{slot: slot, startTime: time.Now()}
		stream.releaseHeavy()
		stream.trackRead(sharedconfig.HeavyStreamThresholdBytes)
		if slot.heavy.Load() != 0 {
			t.Fatalf("heavy marked after release: %d", slot.heavy.Load())
		}
		if stream.heavyState.Load() != heavyReleased {
			t.Fatalf("state = %d, want released", stream.heavyState.Load())
		}
		// A double release must not decrement below zero.
		stream.releaseHeavy()
		if slot.heavy.Load() != 0 {
			t.Fatalf("double release changed counter: %d", slot.heavy.Load())
		}
	})
}

func TestEvaluateSlotHealth(t *testing.T) {
	interval := sharedconfig.HealthCheckInterval
	tr := &HTTP2Transport{}

	newHeavySlot := func() *transportSlot {
		s := &transportSlot{t: &http.Transport{}}
		s.heavy.Store(1)
		return s
	}
	// lowThroughput simulates one health interval carrying 10KB
	// (2KB/s, well below the 64KB/s degraded threshold).
	lowThroughput := func(s *transportSlot) {
		s.bytesRecv.Add(10 * 1024)
		tr.evaluateSlotHealth(0, s, interval, true)
	}
	highThroughput := func(s *transportSlot) {
		s.bytesRecv.Add(2 * 1024 * 1024) // 2MB over 5s = 400KB/s
		tr.evaluateSlotHealth(0, s, interval, true)
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
		tr.evaluateSlotHealth(0, s, interval, false)
		for i := 0; i < sharedconfig.DegradedPersistCycles+2; i++ {
			s.bytesRecv.Add(10 * 1024)
			tr.evaluateSlotHealth(0, s, interval, false)
		}
		if s.degraded.Load() {
			t.Fatal("degraded while link congested")
		}
	})

	t.Run("heavy 0->1 transition resets throughput baseline", func(t *testing.T) {
		s := newHeavySlot()
		s.bytesRecv.Add(50 * 1024) // stale bytes from earlier small streams
		// First sample only resets the baseline.
		tr.evaluateSlotHealth(0, s, interval, true)
		if s.lowCycles != 0 {
			t.Fatalf("lowCycles = %d after baseline reset, want 0", s.lowCycles)
		}
		// A slow interval afterwards counts from the reset point.
		s.bytesRecv.Add(10 * 1024)
		tr.evaluateSlotHealth(0, s, interval, true)
		if s.lowCycles != 1 {
			t.Fatalf("lowCycles = %d, want 1", s.lowCycles)
		}
	})
}

func TestRetireSlotShrinksLiveCount(t *testing.T) {
	s0 := &transportSlot{t: &http.Transport{}}
	s0.active.Store(1)
	s1 := &transportSlot{t: &http.Transport{}}
	s1.degraded.Store(true)
	tr := &HTTP2Transport{slots: []*transportSlot{s0, s1}}
	tr.liveCount.Store(2)

	tr.retireSlot(s1)
	if got := tr.liveCount.Load(); got != 1 {
		t.Fatalf("liveCount = %d, want 1", got)
	}
	if tr.slots[0] != s0 {
		t.Fatal("live slot must stay at the front")
	}

	// Busy slots are never retired.
	s2 := &transportSlot{t: &http.Transport{}}
	s2.active.Store(1)
	s2.degraded.Store(true)
	tr2 := &HTTP2Transport{slots: []*transportSlot{s2}}
	tr2.liveCount.Store(1)
	tr2.retireSlot(s2)
	if got := tr2.liveCount.Load(); got != 1 {
		t.Fatalf("busy slot retired: liveCount = %d", got)
	}
}

func TestLeastActiveSlotRangePrefersHealthyOverDegraded(t *testing.T) {
	t.Run("skips degraded slot when healthy exists", func(t *testing.T) {
		tr := newTestSlots([2]int32{2, 0}, [2]int32{1, 0})
		tr.slots[1].degraded.Store(true)
		if got := tr.leastActiveSlotRange(0, 2); got != tr.slots[0] {
			t.Fatalf("expected healthy slot 0, got active=%d heavy=%d degraded=%v", got.active.Load(), got.heavy.Load(), got.degraded.Load())
		}
	})

	t.Run("prefers heavy-but-not-degraded over degraded", func(t *testing.T) {
		tr := newTestSlots([2]int32{1, 1}, [2]int32{3, 1})
		tr.slots[1].degraded.Store(true)
		if got := tr.leastActiveSlotRange(0, 2); got != tr.slots[0] {
			t.Fatalf("expected non-degraded slot 0, got active=%d degraded=%v", got.active.Load(), got.degraded.Load())
		}
	})

	t.Run("falls back to degraded when nothing else", func(t *testing.T) {
		tr := newTestSlots([2]int32{5, 1}, [2]int32{3, 1})
		tr.slots[0].degraded.Store(true)
		tr.slots[1].degraded.Store(true)
		if got := tr.leastActiveSlotRange(0, 2); got != tr.slots[1] {
			t.Fatalf("expected least-active degraded slot 1, got active=%d", got.active.Load())
		}
	})
}

func TestLeastActiveSlotRangePrefersNonExpiring(t *testing.T) {
	t.Run("skips expiring slot when fresh exists", func(t *testing.T) {
		tr := newTestSlots([2]int32{2, 0}, [2]int32{1, 0})
		tr.slots[1].expiring.Store(true)
		if got := tr.leastActiveSlotRange(0, 2); got != tr.slots[0] {
			t.Fatalf("expected non-expiring slot 0, got active=%d expiring=%v", got.active.Load(), got.expiring.Load())
		}
	})

	t.Run("prefers degraded-but-fresh over expiring", func(t *testing.T) {
		tr := newTestSlots([2]int32{3, 1}, [2]int32{1, 1})
		tr.slots[0].degraded.Store(true)
		tr.slots[1].expiring.Store(true)
		if got := tr.leastActiveSlotRange(0, 2); got != tr.slots[0] {
			t.Fatalf("expected degraded slot 0 over expiring, got active=%d", got.active.Load())
		}
	})

	t.Run("falls back to expiring when nothing else", func(t *testing.T) {
		tr := newTestSlots([2]int32{5, 1}, [2]int32{3, 1})
		tr.slots[0].expiring.Store(true)
		tr.slots[1].expiring.Store(true)
		if got := tr.leastActiveSlotRange(0, 2); got != tr.slots[1] {
			t.Fatalf("expected least-active expiring slot 1, got active=%d", got.active.Load())
		}
	})
}

func TestShouldGrow(t *testing.T) {
	t.Run("heavy slot with single stream does not block growth", func(t *testing.T) {
		tr := newTestSlots([2]int32{1, 1}, [2]int32{8, 0})
		// slot0 is heavy with 1 stream (below threshold), slot1 eligible at
		// threshold: growth must be allowed since new streams avoid slot0.
		if !tr.shouldGrow(0, 2, 4) {
			t.Fatal("expected growth with heavy slot below threshold")
		}
	})

	t.Run("eligible slot below threshold blocks growth", func(t *testing.T) {
		tr := newTestSlots([2]int32{3, 0}, [2]int32{8, 0})
		if tr.shouldGrow(0, 2, 4) {
			t.Fatal("expected no growth while an eligible slot has capacity")
		}
	})

	t.Run("all slots heavy still grows", func(t *testing.T) {
		tr := newTestSlots([2]int32{1, 1}, [2]int32{1, 1})
		if !tr.shouldGrow(0, 2, 4) {
			t.Fatal("expected growth when no eligible slot exists")
		}
	})

	t.Run("degraded and expiring slots do not block growth", func(t *testing.T) {
		tr := newTestSlots([2]int32{1, 0}, [2]int32{8, 0})
		tr.slots[0].degraded.Store(true)
		if !tr.shouldGrow(0, 2, 4) {
			t.Fatal("expected growth with degraded slot below threshold")
		}
		tr2 := newTestSlots([2]int32{1, 0}, [2]int32{8, 0})
		tr2.slots[0].expiring.Store(true)
		if !tr2.shouldGrow(0, 2, 4) {
			t.Fatal("expected growth with expiring slot below threshold")
		}
	})
}

func TestRotationDue(t *testing.T) {
	now := time.Now()
	t.Run("lifetime exceeded", func(t *testing.T) {
		tr := &HTTP2Transport{connLifetime: time.Minute}
		s := &transportSlot{}
		s.expireAt.Store(now.Add(-2 * time.Minute).UnixNano())
		if !tr.rotationDue(s, now) {
			t.Fatal("expected rotation due by age")
		}
	})

	t.Run("bytes exceeded", func(t *testing.T) {
		tr := &HTTP2Transport{connLifetime: time.Hour, connMaxBytes: 1024}
		s := &transportSlot{}
		s.expireAt.Store(now.Add(time.Hour).UnixNano())
		s.connBytesRecv.Store(2048)
		if !tr.rotationDue(s, now) {
			t.Fatal("expected rotation due by bytes")
		}
	})

	t.Run("fresh connection not due", func(t *testing.T) {
		tr := &HTTP2Transport{connLifetime: time.Minute, connMaxBytes: 1024}
		s := &transportSlot{}
		s.expireAt.Store(now.Add(time.Minute).UnixNano())
		s.connBytesRecv.Store(512)
		if tr.rotationDue(s, now) {
			t.Fatal("fresh connection must not rotate")
		}
	})

	t.Run("never dialed slot not due by age", func(t *testing.T) {
		tr := &HTTP2Transport{connLifetime: time.Minute}
		s := &transportSlot{}
		if tr.rotationDue(s, now) {
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
		tr := &HTTP2Transport{connLifetime: time.Minute}
		s := &transportSlot{t: &http.Transport{}}
		s.expireAt.Store(time.Now().Add(-2 * time.Minute).UnixNano())
		s.active.Store(1)
		// First pass: still busy, only mark expiring.
		tr.evaluateRotation(0, s)
		if !s.expiring.Load() {
			t.Fatal("expected expiring mark")
		}
		// Second pass: idle now, rotation completes and clears the mark.
		s.active.Store(0)
		tr.evaluateRotation(0, s)
		if s.expiring.Load() {
			t.Fatal("expected expiring cleared after rotation")
		}
	})

	t.Run("fresh connection not expiring", func(t *testing.T) {
		tr := &HTTP2Transport{connLifetime: time.Hour}
		s := &transportSlot{t: &http.Transport{}}
		s.expireAt.Store(time.Now().Add(time.Hour).UnixNano())
		tr.evaluateRotation(0, s)
		if s.expiring.Load() {
			t.Fatal("fresh connection must not expire")
		}
	})
}
