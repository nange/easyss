package http2

import (
	"errors"
	"io"
	"sync"
	"testing"
)

func newTestStream() (*HTTP2Stream, *io.PipeReader) {
	pr, pw := io.Pipe()
	s := &HTTP2Stream{
		w:      pw,
		respCh: make(chan roundTripResult, 1),
		cancel:  func() {},
		done:    sync.OnceFunc(func() {}),
	}
	return s, pr
}

func TestHTTP2Stream_WriteSurfacesRoundTripErr(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close()
	defer s.Close()

	sentinel := errors.New("tls: handshake failure")
	s.setRoundTripErr(sentinel)

	// Close the reader so the next Write fails with io.ErrClosedPipe.
	pr.Close()

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
	defer pr.Close()
	defer s.Close()

	// rtErr remains nil — Write should return the bare io.ErrClosedPipe.
	pr.Close()

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
	defer pr.Close()
	defer s.Close()

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
	defer pr.Close()
	defer s.Close()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.setRoundTripErr(errors.New("concurrent error"))
		}()
	}
	wg.Wait()

	s.rtErrMu.Lock()
	if s.rtErr == nil {
		t.Error("expected rtErr to be set after concurrent calls")
	}
	s.rtErrMu.Unlock()
}
