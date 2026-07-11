package http2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

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

	mu       sync.Mutex
	r        io.ReadCloser
	respErr  error
	respOnce sync.Once
	closed   bool

	rtErrMu sync.Mutex
	rtErr   error // RoundTrip error, captured for better diagnostics in Write()
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
	if err != nil {
		s.done()
	}
	return n, err
}

func (s *HTTP2Stream) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
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
