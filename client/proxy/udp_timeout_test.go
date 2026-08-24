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
// called, simulating a server that never answers (e.g. an upstream DNS
// server that silently drops queries). Write succeeds so the bootstrap
// handshake completes.
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

// newTimeoutTestServer builds a Socks5Server whose proxied-DNS exchanges run
// with testDNSRespTimeout and whose transport serves the given streams.
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
// receiveLoop defer removes it) or the deadline expires.
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

// TestUDPExchangeDNSResponseTimeout verifies that a proxied-DNS exchange
// with no server response is closed (stream closed, key removed) once
// dnsRespTimeout elapses, so silent upstream DNS servers cannot pile up
// HTTP/2 streams and receiveLoop goroutines.
func TestUDPExchangeDNSResponseTimeout(t *testing.T) {
	bs := newBlockingStream()
	srv := newTimeoutTestServer(t, []transport.Stream{bs})

	key := "127.0.0.1:12345_8.8.8.8:53"
	ue, created, err := srv.getOrCreateUDPExchange(key, "8.8.8.8:53", []byte("dns query payload"))
	if err != nil {
		t.Fatalf("getOrCreateUDPExchange: %v", err)
	}
	if !created {
		t.Fatal("expected exchange to be created")
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	go srv.receiveLoop(ue, nil, clientAddr, "8.8.8.8:53", key, srv.dnsRespTimeout)

	if !srv.hasExchange(key) {
		t.Fatal("expected exchange to be registered before the timeout")
	}

	waitExchangeReaped(t, srv, key)

	if !bs.isClosed() {
		t.Error("expected exchange stream to be closed after response timeout")
	}
}

// TestUDPExchangeNoTimeoutWhenDisabled verifies that respTimeout=0 (the
// non-DNS UDP path) leaves the exchange untouched even past dnsRespTimeout:
// a long downlink silence must not kill regular UDP sessions.
func TestUDPExchangeNoTimeoutWhenDisabled(t *testing.T) {
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
	go srv.receiveLoop(ue, nil, clientAddr, "8.8.8.8:443", key, 0)

	time.Sleep(testDNSRespTimeout * 2)
	if !srv.hasExchange(key) {
		t.Fatal("exchange must not be reaped when the response timeout is disabled")
	}
	if bs.isClosed() {
		t.Error("stream must not be closed when the response timeout is disabled")
	}

	// Tear down: close the exchange so the blocked receiveLoop exits and
	// the key is cleaned up, then wait for the goroutine to finish.
	ue.Close() //nolint:errcheck
	waitExchangeReaped(t, srv, key)
}
