package proxy

import (
	"errors"
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
	s.WarmUp(0, 0, 2*time.Second)

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

	s.WarmUp(0, 0, 2*time.Second)

	if got := tr.warmUpCalls(); got != 0 {
		t.Errorf("expected no transport WarmUp when server is closing, got %d", got)
	}
}

// TestWarmUp_ErrorIsSwallowed verifies the best-effort contract: a failing
// transport warm-up is logged and swallowed, never surfaced to the caller.
func TestWarmUp_ErrorIsSwallowed(t *testing.T) {
	tr := &mockTransport{warmUpErr: errors.New("probe failed")}
	s := newTestSocksServer(tr)

	s.WarmUp(0, 0, 2*time.Second)

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
	s.WarmUp(10*time.Millisecond, 50*time.Millisecond, 2*time.Second)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("warm-up with jitter took too long: %v", elapsed)
	}
	if got := tr.warmUpCalls(); got != 1 {
		t.Errorf("expected 1 transport WarmUp, got %d", got)
	}
}
