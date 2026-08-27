package proxy

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/transport"
)

// blockingStream is a transport.Stream whose Read blocks until Close is
// called, simulating a remote peer that never answers. Write succeeds so a
// bootstrap handshake can complete.
type blockingStream struct {
	mu     sync.Mutex
	closed bool
	wake   chan struct{}
}

func newBlockingStream() *blockingStream {
	return &blockingStream{wake: make(chan struct{})}
}

func (s *blockingStream) Read(p []byte) (int, error) {
	<-s.wake
	return 0, net.ErrClosed
}

func (s *blockingStream) Write(p []byte) (int, error) { return len(p), nil }

func (s *blockingStream) CloseWrite() error { return nil }

func (s *blockingStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.wake)
	}
	return nil
}

func (s *blockingStream) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

var _ transport.Stream = (*blockingStream)(nil)

const testDNSRespTimeout = 200 * time.Millisecond

// newTimeoutTestServer builds a Socks5Server whose shared proxied-DNS
// deadlines run with testDNSRespTimeout and whose transport serves the given
// streams.
func newTimeoutTestServer(t *testing.T, streams []transport.Stream) *Socks5Server {
	t.Helper()
	h := newTestStreamHandler(&mockTransport{streams: streams})
	srv, err := NewSocks5Server("127.0.0.1:0", "", "", h, nil, "", protocol.MethodAES256GCM, true, 10*time.Second, 30*time.Second, testDNSRespTimeout, nil)
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	return srv
}

func (s *Socks5Server) hasExchange(key string) bool {
	s.udpMu.RLock()
	defer s.udpMu.RUnlock()
	_, ok := s.udpExch[key]
	return ok
}

// waitExchangeReaped polls until the key disappears from s.udpExch (the
// receive loop defer removes it) or the deadline expires.
func waitExchangeReaped(t *testing.T, s *Socks5Server, key string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for s.hasExchange(key) {
		if time.Now().After(deadline) {
			t.Fatalf("exchange %q not reaped within deadline", key)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestUDPExchangeNoTimeoutForRegularUDP verifies that a non-DNS UDP exchange
// (the per-client path for games etc.) is left untouched even past
// dnsRespTimeout: a long downlink silence must not kill regular UDP sessions.
// The per-query DNS deadline only applies to the shared DNS stream.
func TestUDPExchangeNoTimeoutForRegularUDP(t *testing.T) {
	bs := newBlockingStream()
	srv := newTimeoutTestServer(t, []transport.Stream{bs})

	key := "127.0.0.1:12345_8.8.8.8:443"
	ue, created, err := srv.getOrCreateUDPExchange(key, "8.8.8.8:443", []byte("udp payload"))
	if err != nil {
		t.Fatalf("getOrCreateUDPExchange: %v", err)
	}
	if !created {
		t.Fatal("expected exchange to be created")
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	go srv.receiveLoop(ue, nil, clientAddr, "8.8.8.8:443", key)

	time.Sleep(testDNSRespTimeout * 2)
	if !srv.hasExchange(key) {
		t.Fatal("exchange must not be reaped for a regular UDP session")
	}
	if bs.isClosed() {
		t.Error("stream must not be closed for a regular UDP session")
	}

	// Tear down: close the exchange so the blocked receiveLoop exits and
	// the key is cleaned up, then wait for the goroutine to finish.
	ue.Close() //nolint:errcheck
	waitExchangeReaped(t, srv, key)
}
