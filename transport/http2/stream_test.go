package http2

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nange/easyss/v3/stats"
)

func newTestStream() (*HTTP2Stream, *io.PipeReader) {
	pr, pw := io.Pipe()
	s := &HTTP2Stream{
		w:      pw,
		respCh: make(chan roundTripResult, 1),
		cancel: func() {},
		done:   sync.OnceFunc(func() {}),
	}
	return s, pr
}

func TestHTTP2Stream_WriteSurfacesRoundTripErr(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	sentinel := errors.New("tls: handshake failure")
	s.setRoundTripErr(sentinel)

	// Close the reader so the next Write fails with io.ErrClosedPipe.
	pr.Close() //nolint:errcheck

	_, err := s.Write([]byte("payload"))
	if err == nil {
		t.Fatal("expected error from Write, got nil")
	}
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("expected error to wrap io.ErrClosedPipe, got: %v", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected error to wrap sentinel error, got: %v", err)
	}
}

func TestHTTP2Stream_WriteNoRoundTripErr(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	// rtErr remains nil — Write should return the bare io.ErrClosedPipe.
	pr.Close() //nolint:errcheck

	_, err := s.Write([]byte("payload"))
	if err == nil {
		t.Fatal("expected error from Write, got nil")
	}
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("expected io.ErrClosedPipe, got: %v", err)
	}
	if err != io.ErrClosedPipe {
		t.Errorf("expected bare io.ErrClosedPipe (no wrapping), got: %v", err)
	}
}

func TestHTTP2Stream_WriteSuccess(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 16)
		n, err := pr.Read(buf)
		if err != nil {
			t.Errorf("unexpected read error: %v", err)
			return
		}
		if string(buf[:n]) != "hello" {
			t.Errorf("read = %q, want %q", buf[:n], "hello")
		}
	}()

	n, err := s.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 5 {
		t.Errorf("write count = %d, want 5", n)
	}
	<-done
}

func TestSetRoundTripErr_Concurrent(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			s.setRoundTripErr(errors.New("concurrent error"))
		})
	}
	wg.Wait()

	s.rtErrMu.Lock()
	if s.rtErr == nil {
		t.Error("expected rtErr to be set after concurrent calls")
	}
	s.rtErrMu.Unlock()
}

// TestHTTP2Stream_ConnBytesCountsBothDirections verifies the connection
// rotation byte counter accumulates uploaded and downloaded bytes alike:
// rotation against conn_max_bytes must trigger for upload-only traffic too,
// since middleboxes throttle by total bytes in either direction.
func TestHTTP2Stream_ConnBytesCountsBothDirections(t *testing.T) {
	slot := &transportSlot{}
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck
	s.slot = slot
	s.startTime = time.Now()

	s.trackRead(1000)
	s.trackWrite(2000)

	if got := slot.connBytes.Load(); got != 3000 {
		t.Fatalf("connBytes = %d, want 3000 (both directions)", got)
	}
	// The throughput health sample stays download-only: bytesRecv must not
	// include uploaded bytes.
	if got := slot.bytesRecv.Load(); got != 1000 {
		t.Fatalf("bytesRecv = %d, want 1000 (download only)", got)
	}
}

// TestHTTP2Stream_TrackWriteNilSlotNoOp guards the nil-slot fast path in
// trackWrite after it started counting connection bytes.
func TestHTTP2Stream_TrackWriteNilSlotNoOp(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	s.trackWrite(1 << 20) // must not panic

	if s.heavyState.Load() != heavyIdle {
		t.Fatal("nil slot must not mark heavy")
	}
}

// TestHTTP2Stream_RecordsPathRTTOnResponse verifies that a successful
// response arriving after MarkBootstrapSent feeds one pure path RTT sample
// (bootstrap record flushed -> response headers arrived), and that a stream
// never stamped stays silent.
func TestHTTP2Stream_RecordsPathRTTOnResponse(t *testing.T) {
	// newTestStream exposes respCh as read-only, so keep a writable handle
	// to inject the response.
	newStream := func() (*HTTP2Stream, chan roundTripResult) {
		s, pr := newTestStream()
		_ = pr
		respCh := make(chan roundTripResult, 1)
		s.respCh = respCh
		return s, respCh
	}

	t.Run("stamped stream records the sample", func(t *testing.T) {
		stats.ResetCounters()
		s, respCh := newStream()
		defer s.Close() //nolint:errcheck

		s.MarkBootstrapSent()
		time.Sleep(2 * time.Millisecond)
		respCh <- roundTripResult{
			resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))},
			err:  nil,
		}

		buf := make([]byte, 16)
		if _, err := s.Read(buf); err != io.EOF {
			t.Fatalf("Read = %v, want io.EOF", err)
		}

		snap := stats.Collect()
		if snap.RTTCount != 1 {
			t.Fatalf("RTTCount = %d, want 1", snap.RTTCount)
		}
		if snap.AvgRTT() < time.Millisecond {
			t.Fatalf("AvgRTT = %v, want >= 1ms", snap.AvgRTT())
		}
	})

	t.Run("unstamped stream records nothing", func(t *testing.T) {
		stats.ResetCounters()
		s, respCh := newStream()
		defer s.Close() //nolint:errcheck

		respCh <- roundTripResult{
			resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))},
			err:  nil,
		}

		buf := make([]byte, 16)
		if _, err := s.Read(buf); err != io.EOF {
			t.Fatalf("Read = %v, want io.EOF", err)
		}

		if got := stats.Collect().RTTCount; got != 0 {
			t.Fatalf("RTTCount = %d, want 0 without MarkBootstrapSent", got)
		}
	})
}

// TestHTTP2Stream_SlotDraining verifies the drain signal reflects the slot's
// eviction marks (expiring/degraded), which drives the proxy's early close of
// idle streams (relay.BidirectionalWithDrain).
func TestHTTP2Stream_SlotDraining(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	slot := &transportSlot{}
	s.slot = slot

	if s.SlotDraining() {
		t.Fatal("fresh slot must not report draining")
	}
	slot.expiring.Store(true)
	if !s.SlotDraining() {
		t.Fatal("expected draining when the slot is expiring")
	}
	slot.expiring.Store(false)
	slot.degraded.Store(true)
	if !s.SlotDraining() {
		t.Fatal("expected draining when the slot is degraded")
	}
	slot.expiring.Store(true)
	if !s.SlotDraining() {
		t.Fatal("expected draining when the slot is expiring+degraded")
	}

	// A stream without a slot must not panic and never drains.
	ns := &HTTP2Stream{}
	if ns.SlotDraining() {
		t.Fatal("nil slot must not report draining")
	}
}
