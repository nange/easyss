package proxy

import (
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

func TestWarmUp_OpensAndClosesExchange(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{},
		},
	}
	s := newTestSocksServer(tr)

	// jitter 0: deterministic for tests.
	s.WarmUp("connectivitycheck.gstatic.com", 0, 0, 2*time.Second)

	if got := tr.openCalls(); got != 1 {
		t.Errorf("expected exactly 1 transport Open (connection warmed), got %d", got)
	}
	if len(s.udpExch) != 0 {
		t.Errorf("expected exchange map to be empty after warm-up, got %d entries", len(s.udpExch))
	}
}

func TestWarmUp_NoopWhenClosing(t *testing.T) {
	tr := &mockTransport{}
	s := newTestSocksServer(tr)
	s.closing.Store(true)

	s.WarmUp("connectivitycheck.gstatic.com", 0, 0, 2*time.Second)

	if got := tr.openCalls(); got != 0 {
		t.Errorf("expected no transport Open when server is closing, got %d", got)
	}
}

func TestWarmUp_NoopWhenExchangeExists(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{},
			&mockStream{},
		},
	}
	s := newTestSocksServer(tr)

	// First call opens and closes the exchange; the second call must not
	// open a new one beyond the first.
	s.WarmUp("connectivitycheck.gstatic.com", 0, 0, 2*time.Second)
	if got := tr.openCalls(); got != 1 {
		t.Fatalf("expected 1 transport Open after first warm-up, got %d", got)
	}

	// Pre-register an exchange for the same key: the warm-up must skip it.
	key := "warmup_0_connectivitycheck.gstatic.com"
	s.udpMu.Lock()
	s.udpExch[key] = &UDPExchange{}
	s.udpMu.Unlock()

	s.WarmUp("connectivitycheck.gstatic.com", 0, 0, 2*time.Second)
	if got := tr.openCalls(); got != 1 {
		t.Errorf("expected no additional transport Open when exchange exists, got %d", got)
	}
}

func TestWarmUp_JitterBounded(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{&mockStream{}},
	}
	s := newTestSocksServer(tr)

	// jitterMax must never exceed the timeout; with a 50ms jitter window the
	// warm-up must still complete (bounded), not hang.
	start := time.Now()
	s.WarmUp("connectivitycheck.gstatic.com", 10*time.Millisecond, 50*time.Millisecond, 2*time.Second)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("warm-up with jitter took too long: %v", elapsed)
	}
	if got := tr.openCalls(); got != 1 {
		t.Errorf("expected 1 transport Open, got %d", got)
	}
}
