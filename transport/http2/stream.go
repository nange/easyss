package http2

import (
	"context"
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
	r      io.ReadCloser
	cancel context.CancelFunc
	done   func()
	mu     sync.Mutex
	respOk bool
}

func (s *HTTP2Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	if s.r == nil && !s.respOk {
		s.mu.Unlock()
		res := <-s.respCh
		if res.err != nil {
			s.done()
			return 0, res.err
		}
		s.mu.Lock()
		s.r = res.resp.Body
		s.respOk = true
		s.mu.Unlock()
	} else {
		s.mu.Unlock()
	}

	if s.r == nil {
		s.done()
		return 0, io.EOF
	}

	n, err := s.r.Read(p)
	if err != nil {
		s.done()
	}
	return n, err
}

func (s *HTTP2Stream) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if err != nil {
		s.done()
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
	if s.r != nil {
		return s.r.Close()
	}
	return nil
}

var _ transport.Stream = (*HTTP2Stream)(nil)
