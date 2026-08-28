package proxy

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nange/easyss/v3/protocol"
	"github.com/txthinking/socks5"
)

// recordingDialer wraps a plain UDP dialer, recording every dialed conn and
// delaying each dial so concurrent datagram handlers overlap inside the
// (map check -> dial -> insert) window of the direct UDP relay path.
type recordingDialer struct {
	mu    sync.Mutex
	conns []net.Conn
	delay time.Duration
}

func (d *recordingDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	time.Sleep(d.delay)
	c, err := net.Dial(network, addr)
	if err == nil {
		d.mu.Lock()
		d.conns = append(d.conns, c)
		d.mu.Unlock()
	}
	return c, err
}

func (d *recordingDialer) dialed() []net.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]net.Conn(nil), d.conns...)
}

func newDirectUDPTestServer(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) *Socks5Server {
	t.Helper()
	h := newTestStreamHandler(&mockTransport{})
	srv, err := NewSocks5Server("127.0.0.1:0", "", "", h, nil, "", protocol.MethodAES256GCM, true, 10*time.Second, 30*time.Second, 0, 0, dial)
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	return srv
}

// startSilentRemoteUDP starts a local UDP "remote" that silently discards
// every datagram, so the relay's read loops never receive data and never
// call sendToClient (which would need a real socks5.Server with a UDPConn).
func startSilentRemoteUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen remote udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

func directTestDatagram(dst string, data byte) *socks5.Datagram {
	host, portStr, _ := net.SplitHostPort(dst)
	port, _ := strconv.Atoi(portStr)
	return socks5.NewDatagram(socks5.ATYPIPv4, net.ParseIP(host).To4(), []byte{byte(port >> 8), byte(port)}, []byte{data})
}

// TestDirectUDPRelayConcurrentDial verifies that two datagrams for the same
// (client, target) key handled concurrently create exactly one direct UDP
// session. The pre-fix code raced between the map check and the insert, so
// both handlers dialed: one socket was orphaned (leaking it plus its read
// goroutine for up to the read-idle deadline) and the orphan's cleanup
// then deleted the LIVE map entry, churning a fresh socket every ~2 minutes
// for long-lived flows (QUIC, games, VoIP).
func TestDirectUDPRelayConcurrentDial(t *testing.T) {
	dst := startSilentRemoteUDP(t)

	d := &recordingDialer{delay: 80 * time.Millisecond}
	srv := newDirectUDPTestServer(t, d.dial)

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43210}
	key := "direct_" + clientAddr.String() + "_" + dst

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.directUDPRelay(&socks5.Server{}, clientAddr, directTestDatagram(dst, 1), dst); err != nil {
				t.Errorf("directUDPRelay: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := len(d.dialed()); got != 1 {
		t.Fatalf("dialed %d UDP sockets for one session, want 1 (duplicate dial orphans a socket and its read goroutine)", got)
	}

	srv.udpMu.RLock()
	dc, ok := srv.directUDP[key]
	srv.udpMu.RUnlock()
	if !ok || dc == nil {
		t.Fatal("direct UDP session not registered in the map")
	}
}

// TestDirectUDPRelayStaleReadLoopKeepsLiveEntry verifies that a read loop
// exiting for a socket it no longer owns must not delete the map entry of
// the live session. Pre-fix, the loop's defer deleted the entry blindly, so
// the session was silently dropped while its socket kept lingering.
func TestDirectUDPRelayStaleReadLoopKeepsLiveEntry(t *testing.T) {
	dst := startSilentRemoteUDP(t)

	d := &recordingDialer{delay: 0}
	srv := newDirectUDPTestServer(t, d.dial)

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43211}
	key := "direct_" + clientAddr.String() + "_" + dst

	if err := srv.directUDPRelay(&socks5.Server{}, clientAddr, directTestDatagram(dst, 1), dst); err != nil {
		t.Fatalf("directUDPRelay: %v", err)
	}
	srv.udpMu.RLock()
	live, ok := srv.directUDP[key]
	srv.udpMu.RUnlock()
	if !ok || live == nil {
		t.Fatal("live session missing before stale loop test")
	}

	// A stale socket for the same key that is NOT the map entry (this is
	// what the duplicate-dial race produced): its read loop must exit
	// without evicting the live session.
	staleConn, err := srv.directDialContext(context.Background(), "udp", dst)
	if err != nil {
		t.Fatalf("dial stale conn: %v", err)
	}
	stale := &directUDPConn{conn: staleConn}
	go srv.directUDPReadLoop(&socks5.Server{}, clientAddr, dst, key, stale)
	_ = staleConn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		srv.udpMu.RLock()
		_, ok := srv.directUDP[key]
		srv.udpMu.RUnlock()
		if !ok {
			t.Fatal("stale read loop deleted the live session's map entry")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // let any late delete settle
	srv.udpMu.RLock()
	_, ok = srv.directUDP[key]
	srv.udpMu.RUnlock()
	if !ok {
		t.Fatal("live session's map entry disappeared after stale loop exit")
	}

	// Positive control: the OWNED loop's exit must still clean up its entry.
	_ = live.conn.Close()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		srv.udpMu.RLock()
		_, ok = srv.directUDP[key]
		srv.udpMu.RUnlock()
		if !ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("owned read loop did not delete its map entry on exit")
}
