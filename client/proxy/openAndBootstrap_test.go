package proxy

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/transport"
)

type mockStream struct {
	writeErr error
	written  []byte
}

func (s *mockStream) Read(p []byte) (int, error) { return 0, io.EOF }
func (s *mockStream) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	s.written = append(s.written, p...)
	return len(p), nil
}
func (s *mockStream) CloseWrite() error { return nil }
func (s *mockStream) Close() error      { return nil }

type mockTransport struct {
	mu        sync.Mutex
	openCount int
	streams   []transport.Stream
	openErrs  []error
}

func (m *mockTransport) Open(ctx context.Context, req transport.OpenRequest) (transport.Stream, error) {
	m.mu.Lock()
	idx := m.openCount
	m.openCount++
	m.mu.Unlock()

	if idx < len(m.openErrs) && m.openErrs[idx] != nil {
		return nil, m.openErrs[idx]
	}
	if idx < len(m.streams) {
		return m.streams[idx], nil
	}
	return &mockStream{}, nil
}

func (m *mockTransport) CloseIdle()                      {}
func (m *mockTransport) Stats() transport.TransportStats { return transport.TransportStats{} }
func (m *mockTransport) Close() error                    { return nil }

func (m *mockTransport) openCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.openCount
}

func newTestStreamHandler(tr transport.Transport) *StreamHandler {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return NewStreamHandler(tr, key, shaper.Config{}, 0)
}

func TestOpenAndBootstrap_SuccessFirstTry(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{},
		},
	}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bs == nil {
		t.Fatal("expected non-nil bootstrapSession")
	}
	if tr.openCalls() != 1 {
		t.Errorf("expected 1 Open call, got %d", tr.openCalls())
	}
	defer bs.stream.Close()
}

func TestOpenAndBootstrap_RetryOnErrClosedPipe(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{writeErr: io.ErrClosedPipe},
			&mockStream{},
		},
	}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if bs == nil {
		t.Fatal("expected non-nil bootstrapSession")
	}
	if tr.openCalls() != 2 {
		t.Errorf("expected 2 Open calls, got %d", tr.openCalls())
	}
	defer bs.stream.Close()
}

func TestOpenAndBootstrap_NoRetryOnNonClosedPipeErr(t *testing.T) {
	otherErr := errors.New("some write error")
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{writeErr: otherErr},
		},
	}
	h := newTestStreamHandler(tr)

	_, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, otherErr) {
		t.Errorf("expected error to wrap otherErr, got: %v", err)
	}
	if tr.openCalls() != 1 {
		t.Errorf("expected 1 Open call (no retry), got %d", tr.openCalls())
	}
}

func TestOpenAndBootstrap_AllRetriesFail(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{writeErr: io.ErrClosedPipe},
			&mockStream{writeErr: io.ErrClosedPipe},
		},
	}
	h := newTestStreamHandler(tr)

	_, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("expected error to wrap io.ErrClosedPipe, got: %v", err)
	}
	if tr.openCalls() != 2 {
		t.Errorf("expected 2 Open calls (max retries), got %d", tr.openCalls())
	}
}

func TestOpenAndBootstrap_OpenFailureNoRetry(t *testing.T) {
	openErr := errors.New("transport unavailable")
	tr := &mockTransport{
		openErrs: []error{openErr},
	}
	h := newTestStreamHandler(tr)

	_, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, openErr) {
		t.Errorf("expected error to wrap openErr, got: %v", err)
	}
	if tr.openCalls() != 1 {
		t.Errorf("expected 1 Open call, got %d", tr.openCalls())
	}
}

// saltCapturingTransport wraps a Transport and records the Salt from each Open call.
type saltCapturingTransport struct {
	inner transport.Transport
	mu    sync.Mutex
	salts []string
}

func (t *saltCapturingTransport) Open(ctx context.Context, req transport.OpenRequest) (transport.Stream, error) {
	t.mu.Lock()
	t.salts = append(t.salts, req.Salt)
	t.mu.Unlock()
	return t.inner.Open(ctx, req)
}

func (t *saltCapturingTransport) CloseIdle()                      {}
func (t *saltCapturingTransport) Stats() transport.TransportStats { return transport.TransportStats{} }
func (t *saltCapturingTransport) Close() error                    { return t.inner.Close() }

func TestOpenAndBootstrap_FreshSaltPerAttempt(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{writeErr: io.ErrClosedPipe},
			&mockStream{},
		},
	}
	wrapped := &saltCapturingTransport{inner: tr}
	h := newTestStreamHandler(wrapped)

	bs, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer bs.stream.Close()

	wrapped.mu.Lock()
	defer wrapped.mu.Unlock()
	if len(wrapped.salts) != 2 {
		t.Fatalf("expected 2 salts, got %d", len(wrapped.salts))
	}
	if wrapped.salts[0] == "" || wrapped.salts[1] == "" {
		t.Error("expected non-empty salts")
	}
	if wrapped.salts[0] == wrapped.salts[1] {
		t.Error("expected different salts for each retry attempt")
	}
}
