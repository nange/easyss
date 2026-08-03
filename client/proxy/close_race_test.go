package proxy

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/nange/easyss/v3/protocol"
)

// TestSocks5CloseRacingStart guards against closing a socks5 server right
// after starting it, which races with the accept-loop setup inside the
// txthinking/socks5 runnergroup library. GOMAXPROCS(1) forces the Close
// call to run before the Start goroutine sets up its accept loop: without
// synchronization the listener leaks (the port keeps accepting) or the
// Shutdown deadlocks. After Close returns, the port must be closed.
func TestSocks5CloseRacingStart(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)

	for i := 0; i < 5; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := l.Addr().String()
		l.Close()

		h := newTestStreamHandler(&mockTransport{})
		srv, err := NewSocks5Server(addr, "", "", h, nil, "", protocol.MethodAES256GCM, true, 10*time.Second, 30*time.Second, nil)
		if err != nil {
			t.Fatalf("NewSocks5Server #%d: %v", i, err)
		}
		srv.MarkStarted()
		go srv.Start() //nolint:errcheck
		_ = srv.Close()

		// Give a leaked accept loop a chance to run, then verify the
		// port is actually closed.
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
			if err == nil {
				c.Close()
				t.Fatalf("iteration #%d: server still listening on %s after Close", i, addr)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}
