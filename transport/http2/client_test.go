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
	}, time.Second, nil)
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

func TestTrackBytesMarksSlotHeavy(t *testing.T) {
	// Fast path: a large transfer is marked as soon as it crosses the
	// cumulative size threshold.
	t.Run("fast large transfer marks at size threshold", func(t *testing.T) {
		slot := &transportSlot{}
		stream := &HTTP2Stream{slot: slot, startTime: time.Now()}

		// Below the fast threshold and too young for the slow path: no mark.
		stream.trackBytes(sharedconfig.HeavyStreamThresholdBytes - 1)
		if slot.heavy.Load() != 0 || stream.heavyFlag.Load() {
			t.Fatalf("marked heavy before threshold: slot.heavy=%d flag=%v", slot.heavy.Load(), stream.heavyFlag.Load())
		}

		// Crossing the fast threshold: mark exactly once.
		stream.trackBytes(2)
		if slot.heavy.Load() != 1 || !stream.heavyFlag.Load() {
			t.Fatalf("expected heavy mark after threshold: slot.heavy=%d flag=%v", slot.heavy.Load(), stream.heavyFlag.Load())
		}

		// Further transfers must not double-mark.
		stream.trackBytes(64 * 1024)
		if slot.heavy.Load() != 1 {
			t.Fatalf("heavy marked more than once: %d", slot.heavy.Load())
		}

		// Release on stream end: mirrors the doneOnce logic in Open.
		if stream.heavyFlag.Swap(false) {
			slot.heavy.Add(-1)
		}
		if slot.heavy.Load() != 0 {
			t.Fatalf("heavy mark not released: %d", slot.heavy.Load())
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
		stream.trackBytes(sharedconfig.HeavyStreamSlowThresholdBytes - 1)
		if slot.heavy.Load() != 0 {
			t.Fatalf("marked heavy below slow threshold: %d", slot.heavy.Load())
		}

		// At or above the slow threshold with sufficient age: mark once.
		stream.trackBytes(1024)
		if slot.heavy.Load() != 1 || !stream.heavyFlag.Load() {
			t.Fatalf("expected heavy mark on slow path: slot.heavy=%d flag=%v", slot.heavy.Load(), stream.heavyFlag.Load())
		}
	})

	// A young stream below the fast threshold must not be marked.
	t.Run("young stream below fast threshold not marked", func(t *testing.T) {
		slot := &transportSlot{}
		stream := &HTTP2Stream{slot: slot, startTime: time.Now()}

		stream.trackBytes(sharedconfig.HeavyStreamSlowThresholdBytes)
		if slot.heavy.Load() != 0 {
			t.Fatalf("young stream marked heavy: %d", slot.heavy.Load())
		}
	})

	// Nil slot is a no-op (e.g. test-constructed streams).
	t.Run("nil slot no-op", func(t *testing.T) {
		noSlot := &HTTP2Stream{}
		noSlot.trackBytes(sharedconfig.HeavyStreamThresholdBytes)
		if noSlot.heavyFlag.Load() {
			t.Fatal("nil slot must not be marked heavy")
		}
	})
}
