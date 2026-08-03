package runner

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/config"
)

func testConfig() *config.ClientConfig {
	cfg := config.DefaultConfig()
	cfg.Servers = []*config.ServerProfile{{
		Address:  "example.com",
		Port:     443,
		Password: "test-password",
		Method:   "aes-256-gcm",
		Default:  true,
	}}
	// Skip the IPv6 resolution via direct DNS servers during client init,
	// which would otherwise block for seconds per query in tests.
	cfg.Routing.IPV6Rule = "disable"
	return cfg
}

// waitAccept polls addr until the server has started accepting connections.
// Stopping a socks5 server before its accept loop is up deadlocks inside the
// txthinking/socks5 runnergroup library, so tests must wait before Stop.
func waitAccept(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server did not start listening on %s", addr)
}

// occupyTCPPort returns a listener bound to a random 127.0.0.1 port that
// stays open for the duration of the test, so the port is unavailable.
func occupyTCPPort(t *testing.T) (net.Listener, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, l.Addr().(*net.TCPAddr).Port
}

// freePort returns a port that is currently available for binding.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// occupyUDPPort returns a packet conn bound to a random 127.0.0.1 UDP port
// that stays open for the duration of the test.
func occupyUDPPort(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

func TestRunFailsFastOnSocksPortConflict(t *testing.T) {
	_, port := occupyTCPPort(t)
	cfg := testConfig()
	cfg.Local.SocksPort = port
	cfg.Local.HTTPPort = 0

	core, err := Run(cfg)
	if err == nil {
		core.Stop()
		t.Fatal("expected error when socks port is occupied")
	}
	if !strings.Contains(err.Error(), "socks5 server listen") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunFailsFastOnHTTPPortConflict(t *testing.T) {
	_, httpPort := occupyTCPPort(t)
	cfg := testConfig()
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = httpPort

	core, err := Run(cfg)
	if err == nil {
		core.Stop()
		t.Fatal("expected error when http port is occupied")
	}
	if !strings.Contains(err.Error(), "http proxy server listen") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrebindUDP(t *testing.T) {
	pc := occupyUDPPort(t)
	if err := prebindUDP(pc.LocalAddr().String()); err == nil {
		t.Fatal("expected error when udp port is occupied")
	}

	freePc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	freeAddr := freePc.LocalAddr().String()
	freePc.Close()

	if err := prebindUDP(freeAddr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunOKWhenPortsAreFree(t *testing.T) {
	cfg := testConfig()
	socksPort := freePort(t)
	httpPort := freePort(t)
	cfg.Local.SocksPort = socksPort
	cfg.Local.HTTPPort = httpPort

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if core == nil {
		t.Fatal("core is nil")
	}
	waitAccept(t, "127.0.0.1:"+strconv.Itoa(socksPort))
	core.Stop()
}
