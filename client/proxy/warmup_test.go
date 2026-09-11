package proxy

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
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
// transport exactly once: the proxy layer only bounds the probe with a
// deadline and delegates, the transport primes its own pools.
func TestWarmUp_WarmsTransport(t *testing.T) {
	tr := &mockTransport{}
	s := newTestSocksServer(tr)

	if err := s.WarmUp(2 * time.Second); err != nil {
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
	if err := s.WarmUp(2 * time.Second); err != nil {
		t.Errorf("expected nil when server is closing, got %v", err)
	}

	if got := tr.warmUpCalls(); got != 0 {
		t.Errorf("expected no transport WarmUp when server is closing, got %d", got)
	}
}

// TestWarmUp_NilServerIsNotAFailure covers the socks_port = 0 shape: there is
// no proxy server to warm, which must never surface as an error.
func TestWarmUp_NilServerIsNotAFailure(t *testing.T) {
	var s *Socks5Server

	if err := s.WarmUp(2 * time.Second); err != nil {
		t.Errorf("expected nil for a nil server, got %v", err)
	}
}

// TestWarmUp_ErrorIsReturned verifies the best-effort contract: the failure is
// logged here and handed back to the caller (which may swallow it), but the
// error is never replaced or dropped by the proxy layer.
func TestWarmUp_ErrorIsReturned(t *testing.T) {
	tr := &mockTransport{warmUpErr: errors.New("probe failed")}
	s := newTestSocksServer(tr)

	err := s.WarmUp(2 * time.Second)

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

// TestWarmUp_DefaultTimeoutWhenZero verifies the fallback: a zero (or
// negative) timeout must not turn into an already-expired context, so the
// probe is bounded by config.WarmUpTimeout instead.
func TestWarmUp_DefaultTimeoutWhenZero(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		tr := &mockTransport{}
		s := newTestSocksServer(tr)

		start := time.Now()
		err := s.WarmUp(timeout)
		if err != nil {
			t.Fatalf("timeout=%v: unexpected error from a confirmed warm-up: %v", timeout, err)
		}
		if got := tr.warmUpCalls(); got != 1 {
			t.Errorf("timeout=%v: expected 1 transport WarmUp, got %d", timeout, got)
			continue
		}

		deadline := tr.warmUpDeadlineOf()
		if deadline.IsZero() {
			t.Errorf("timeout=%v: probe context carried no deadline", timeout)
			continue
		}
		remaining := deadline.Sub(start)
		if remaining <= 0 {
			t.Errorf("timeout=%v: probe deadline already expired", timeout)
		}
		if remaining > config.WarmUpTimeout {
			t.Errorf("timeout=%v: probe deadline %v exceeds the default %v", timeout, remaining, config.WarmUpTimeout)
		}
	}
}
