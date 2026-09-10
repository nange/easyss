package proxy

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/transport"
	"golang.org/x/sync/singleflight"
)

// newTestSocksServer builds a Socks5Server wired to a mock transport so
// WarmUp can be exercised without any real network.
func newTestSocksServer(tr transport.Transport) *Socks5Server {
	s := &Socks5Server{
		handler:        newTestStreamHandler(tr),
		method:         protocol.MethodAES256GCM,
		udpExch:        make(map[string]*UDPExchange),
		quit:           make(chan struct{}),
		dnsRespTimeout: 0,
	}
	s.udpExchangeSF = singleflight.Group{}
	s.directUDPSF = singleflight.Group{}
	return s
}

// TestWarmUp_WarmsTransport verifies that WarmUp hands the work to the
// transport exactly once: the proxy layer only jitters and delegates, the
// transport primes its own pools.
func TestWarmUp_WarmsTransport(t *testing.T) {
	tr := &mockTransport{}
	s := newTestSocksServer(tr)

	// jitter 0: deterministic for tests.
	if err := s.WarmUp(0, 0, 2*time.Second); err != nil {
		t.Fatalf("unexpected error from a confirmed warm-up: %v", err)
	}

	if got := tr.warmUpCalls(); got != 1 {
		t.Errorf("expected exactly 1 transport WarmUp, got %d", got)
	}
	if got := tr.openCalls(); got != 0 {
		t.Errorf("expected no transport Open, got %d", got)
	}
	if len(s.udpExch) != 0 {
		t.Errorf("expected exchange map to be empty after warm-up, got %d entries", len(s.udpExch))
	}
}

func TestWarmUp_NoopWhenClosing(t *testing.T) {
	tr := &mockTransport{}
	s := newTestSocksServer(tr)
	s.closing.Store(true)

	// A skipped warm-up is not a failure: closing returns nil, never an error.
	if err := s.WarmUp(0, 0, 2*time.Second); err != nil {
		t.Errorf("expected nil when server is closing, got %v", err)
	}

	if got := tr.warmUpCalls(); got != 0 {
		t.Errorf("expected no transport WarmUp when server is closing, got %d", got)
	}
}

// TestWarmUp_ErrorIsReturned verifies the best-effort contract: the failure is
// logged here and handed back to the caller (which may swallow it), but the
// error is never replaced or dropped by the proxy layer.
func TestWarmUp_ErrorIsReturned(t *testing.T) {
	tr := &mockTransport{warmUpErr: errors.New("probe failed")}
	s := newTestSocksServer(tr)

	err := s.WarmUp(0, 0, 2*time.Second)

	if err == nil {
		t.Fatal("expected the transport warm-up error to be returned, got nil")
	}
	if !strings.Contains(err.Error(), "probe failed") {
		t.Errorf("expected the transport error to be preserved, got %v", err)
	}
	if got := tr.warmUpCalls(); got != 1 {
		t.Errorf("expected 1 transport WarmUp attempt, got %d", got)
	}
}

func TestWarmUp_JitterBounded(t *testing.T) {
	tr := &mockTransport{}
	s := newTestSocksServer(tr)

	// With a 50ms jitter window the warm-up must still complete (bounded),
	// not hang, and reach the transport exactly once.
	start := time.Now()
	if err := s.WarmUp(10*time.Millisecond, 50*time.Millisecond, 2*time.Second); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("warm-up with jitter took too long: %v", elapsed)
	}
	if got := tr.warmUpCalls(); got != 1 {
		t.Errorf("expected 1 transport WarmUp, got %d", got)
	}
}

// TestWarmUp_QuitDuringJitterIsNotAnError verifies the shutdown path: when the
// server quits while the warm-up is waiting for its jitter, the warm-up is
// reported as skipped (nil), so a deliberate Stop never surfaces as a failure.
func TestWarmUp_QuitDuringJitterIsNotAnError(t *testing.T) {
	tr := &mockTransport{}
	s := newTestSocksServer(tr)

	close(s.quit)

	if err := s.WarmUp(time.Second, 2*time.Second, 2*time.Second); err != nil {
		t.Errorf("expected nil when quit during jitter, got %v", err)
	}
	if got := tr.warmUpCalls(); got != 0 {
		t.Errorf("expected no transport WarmUp after quit, got %d", got)
	}
}
