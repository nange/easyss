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

	mu       sync.Mutex
	r        io.ReadCloser
	respErr  error
	respOnce sync.Once
	closed   bool

	rtErrMu sync.Mutex
	rtErr   error // RoundTrip error, captured for better diagnostics in Write()

	// Heavy-stream tracking: once the stream qualifies as heavy (fast large
	// transfer, or slow transfer on a poor link), it marks its slot so that
	// new streams avoid sharing that connection.
	startTime   time.Time
	transferred atomic.Int64
	heavyOnce   sync.Once
	heavyFlag   atomic.Bool
}

// trackRead accumulates downloaded bytes: on the slot (transport health
// signal) and in the heavy-stream detector.
func (s *HTTP2Stream) trackRead(n int) {
	if s.slot == nil || n <= 0 {
		return
	}
	s.slot.bytesRecv.Add(int64(n))
	s.accumulate(n)
}

// trackWrite accumulates uploaded bytes into the heavy-stream detector.
func (s *HTTP2Stream) trackWrite(n int) {
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
	fast := total >= sharedconfig.HeavyStreamThresholdBytes
	slow := total >= sharedconfig.HeavyStreamSlowThresholdBytes &&
		time.Since(s.startTime) >= sharedconfig.HeavyStreamMinAge
	if !fast && !slow {
		return
	}
	s.heavyOnce.Do(func() {
		s.heavyFlag.Store(true)
		s.slot.heavy.Add(1)
	})
}

// setRoundTripErr stores the RoundTrip error for use by Write() when the pipe
// write fails with io.ErrClosedPipe.
func (s *HTTP2Stream) setRoundTripErr(err error) {
	s.rtErrMu.Lock()
	s.rtErr = err
	s.rtErrMu.Unlock()
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
