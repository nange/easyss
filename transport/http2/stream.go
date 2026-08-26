package http2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

type roundTripResult struct {
	resp *http.Response
	err  error
}

type HTTP2Stream struct {
	w      *io.PipeWriter
	respCh <-chan roundTripResult
	cancel context.CancelFunc
	done   func()
	slot   *transportSlot

	// bootstrapSentAt is the moment the client finished flushing the
	// encrypted bootstrap record (the request body). The server answers
	// with the response headers before dialing the origin, so the time
	// between this stamp and the response arrival is the pure client<->server
	// path RTT (no origin time). Stored as UnixNano; 0 means never stamped.
	bootstrapSentAt atomic.Int64

	mu       sync.Mutex
	r        io.ReadCloser
	respErr  error
	respOnce sync.Once
	closed   bool

	rtErrMu sync.Mutex
	rtErr   error // RoundTrip error, captured for better diagnostics in Write()

	// Heavy-stream tracking: once the stream qualifies as heavy (fast large
	// transfer, or slow transfer on a poor link), it marks its slot so that
	// new streams avoid sharing that connection. See heavyIdle/heavyMarked/
	// heavyReleased below.
	startTime   time.Time
	transferred atomic.Int64
	heavyMu     sync.Mutex
	heavyState  atomic.Int32
}

// Heavy-stream state machine: a stream transitions heavyIdle -> heavyMarked
// the first time it qualifies as heavy, and heavyMarked -> heavyReleased
// when it closes. The mutex pairs each transition with its slot counter
// update, so slot.heavy can never leak regardless of how Read/Write/Close
// interleave.
const (
	heavyIdle     int32 = iota // stream never qualified as heavy
	heavyMarked                // qualified: slot.heavy incremented
	heavyReleased              // closed: slot.heavy decremented if marked
)

// trackRead accumulates downloaded bytes: on the slot (transport health and
// connection rotation signals) and in the heavy-stream detector.
func (s *HTTP2Stream) trackRead(n int) {
	if s.slot == nil || n <= 0 {
		return
	}
	s.slot.bytesRecv.Add(int64(n))
	s.slot.connBytes.Add(int64(n))
	s.accumulate(n)
}

// trackWrite accumulates uploaded bytes: into the connection rotation
// counter (rotation must trigger for upload-heavy connections too, since
// middleboxes throttle by total bytes in either direction) and the
// heavy-stream detector.
func (s *HTTP2Stream) trackWrite(n int) {
	if s.slot == nil || n <= 0 {
		return
	}
	s.slot.connBytes.Add(int64(n))
	s.accumulate(n)
}

// accumulate feeds the heavy-stream detector and marks the owning slot as
// heavy the first time the stream qualifies: either it crossed the fast
// size threshold, or it has been alive long enough carrying at least the
// slow threshold (slow links make even small transfers long-lived).
func (s *HTTP2Stream) accumulate(n int) {
	if s.slot == nil || n <= 0 {
		return
	}
	total := s.transferred.Add(int64(n))
	// Fast path: marking happens at most once per stream; once the state
	// left heavyIdle (marked or released) there is nothing left to do.
	if s.heavyState.Load() != heavyIdle {
		return
	}
	fast := total >= sharedconfig.HeavyStreamThresholdBytes
	slow := total >= sharedconfig.HeavyStreamSlowThresholdBytes &&
		time.Since(s.startTime) >= sharedconfig.HeavyStreamMinAge
	if !fast && !slow {
		return
	}
	s.heavyMu.Lock()
	defer s.heavyMu.Unlock()
	if s.heavyState.CompareAndSwap(heavyIdle, heavyMarked) {
		s.slot.heavy.Add(1)
	}
}

// releaseHeavy releases the slot's heavy mark exactly once per stream. It
// is called from the stream's done callback (guarded by sync.OnceFunc),
// while accumulate may run concurrently from Read/Write. The mutex pairs
// each state transition with its counter update so slot.heavy cannot leak.
func (s *HTTP2Stream) releaseHeavy() {
	if s.slot == nil {
		return
	}
	s.heavyMu.Lock()
	defer s.heavyMu.Unlock()
	switch s.heavyState.Load() {
	case heavyMarked:
		s.heavyState.Store(heavyReleased)
		s.slot.heavy.Add(-1)
	case heavyIdle:
		s.heavyState.Store(heavyReleased)
	}
}

// setRoundTripErr stores the RoundTrip error for use by Write() when the pipe
// write fails with io.ErrClosedPipe.
func (s *HTTP2Stream) setRoundTripErr(err error) {
	s.rtErrMu.Lock()
	s.rtErr = err
	s.rtErrMu.Unlock()
}

// MarkBootstrapSent stamps the moment the bootstrap record was flushed to
// the transport. The response headers arrive roughly one path RTT later (the
// server answers before dialing the origin), which Read() records as the
// pure client<->server RTT sample.
func (s *HTTP2Stream) MarkBootstrapSent() {
	s.bootstrapSentAt.Store(time.Now().UnixNano())
}

func (s *HTTP2Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	needResp := s.r == nil && s.respErr == nil
	s.mu.Unlock()

	if needResp {
		s.respOnce.Do(func() {
			res := <-s.respCh
			s.mu.Lock()
			if res.err != nil {
				s.respErr = res.err
			} else {
				s.r = res.resp.Body
				// Response headers arrived: with MarkBootstrapSent stamped
				// (bootstrap record flushed) this is the pure path RTT —
				// the server commits the response before dialing the origin.
				if t0 := s.bootstrapSentAt.Load(); t0 > 0 {
					stats.RecordRTT(time.Since(time.Unix(0, t0)))
				}
			}
			// If Close() ran while we were blocked waiting for the response, the
			// response body just arrived but nobody will ever read or close it.
			// Close it now to release the HTTP/2 stream and its buffers, and
			// surface a closed error to the caller.
			if s.closed && s.r != nil {
				_ = s.r.Close()
				s.r = nil
				if s.respErr == nil {
					s.respErr = io.ErrClosedPipe
				}
			}
			s.mu.Unlock()
		})
	}

	s.mu.Lock()
	r := s.r
	respErr := s.respErr
	closed := s.closed
	s.mu.Unlock()

	if closed {
		return 0, io.ErrClosedPipe
	}
	if r == nil {
		s.done()
		if respErr != nil {
			return 0, respErr
		}
		return 0, io.EOF
	}

	n, err := r.Read(p)
	if n > 0 {
		s.trackRead(n)
	}
	if err != nil {
		s.done()
	}
	return n, err
}

func (s *HTTP2Stream) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if n > 0 {
		s.trackWrite(n)
	}
	if err != nil {
		s.done()
		if errors.Is(err, io.ErrClosedPipe) {
			s.rtErrMu.Lock()
			rtErr := s.rtErr
			s.rtErrMu.Unlock()
			if rtErr != nil {
				// Wrap BOTH errors so callers can still match io.ErrClosedPipe
				// for retry decisions, while also seeing the root cause.
				return n, fmt.Errorf("%w: %w", io.ErrClosedPipe, rtErr)
			}
		}
	}
	return n, err
}

func (s *HTTP2Stream) CloseWrite() error {
	return s.w.Close()
}

func (s *HTTP2Stream) Close() error {
	defer s.done()
	s.cancel()
	_ = s.w.Close()

	s.mu.Lock()
	r := s.r
	s.closed = true
	s.mu.Unlock()

	if r != nil {
		return r.Close()
	}
	return nil
}

var _ transport.Stream = (*HTTP2Stream)(nil)

// SlotDraining reports whether the stream's slot is due for eviction: the
// connection exceeded its lifetime or bytes limit (expiring) or was confirmed
// persistently slow (degraded), so it should be recycled. The proxy layer
// asserts transport.SlotDrainingStream on the stream and closes idle streams
// early via relay.BidirectionalWithDrain, so lingering keep-alive and
// half-closed connections cannot postpone the slot's rotation/retirement
// until the full relay idle timeout. Active streams are never drained: the
// relay only closes them once they have been idle for ExpiringStreamDrainIdle.
func (s *HTTP2Stream) SlotDraining() bool {
	return s.slot != nil && (s.slot.expiring.Load() || s.slot.degraded.Load())
}
