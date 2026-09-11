package runner

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/proxy"
)

func testConfig() *config.ClientConfig {
	cfg := config.DefaultConfig()
	cfg.Servers = []*config.ServerProfile{{
		// A literal IP keeps startup-side DNS work out of the tests:
		// resolveServerDomain (and the IPv6 resolution in client.New) both
		// skip literal IPs, so tests never issue real DNS queries.
		Address:  "127.0.0.1",
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

// TestStopImmediatelyAfterRun guards against the deadlock that occurs when
// Socks5Server.Close races with the Start goroutine's accept loop setup.
// GOMAXPROCS(1) forces the main goroutine to run to the point of Shutdown
// before the server goroutine sets up its accept loop, deterministically
// exposing the race. Run must remain safe to stop right after startup.
func TestStopImmediatelyAfterRun(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)

	for i := range 5 {
		cfg := testConfig()
		cfg.Local.SocksPort = freePort(t)
		cfg.Local.HTTPPort = 0

		core, err := Run(cfg)
		if err != nil {
			t.Fatalf("Run #%d: %v", i, err)
		}
		core.Stop()
	}
}

// occupyTCPPort returns a listener bound to a random 127.0.0.1 port that
// stays open for the duration of the test, so the port is unavailable.
func occupyTCPPort(t *testing.T) (net.Listener, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() }) //nolint:errcheck
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
	l.Close() //nolint:errcheck
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
	t.Cleanup(func() { pc.Close() }) //nolint:errcheck
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
	freePc.Close() //nolint:errcheck

	if err := prebindUDP(freeAddr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunOKWhenPortsAreFree(t *testing.T) {
	cfg := testConfig()
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = freePort(t)

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if core == nil {
		t.Fatal("core is nil")
	}
	core.Stop()
}

// stubWarmUp replaces warmUpCore so the dispatch logic can be asserted without
// any network. It counts the probes, releases done when a stubbed probe
// returns, and restores the previous implementation when the test ends.
//
// StartWarmUp captures warmUpCore at dispatch time, so a probe that outlives
// its test still calls this stub even after the cleanup below restores the
// package var.
func stubWarmUp(t *testing.T, err error) (*atomic.Int64, *waitSignal) {
	t.Helper()

	old := warmUpCore
	calls := &atomic.Int64{}
	done := &waitSignal{done: make(chan struct{})}

	warmUpCore = func(*proxy.Socks5Server, time.Duration) error {
		calls.Add(1)
		done.close()
		return err
	}
	t.Cleanup(func() { warmUpCore = old })

	return calls, done
}

// waitSignal reports that a stubbed probe returned. It is closed by the stub
// goroutine and safe to close more than once.
type waitSignal struct {
	once sync.Once
	done chan struct{}
}

func (w *waitSignal) close() {
	w.once.Do(func() { close(w.done) })
}

// waitProbe blocks until the stubbed probe returned, failing the test if it
// never did.
func (w *waitSignal) waitProbe(t *testing.T, what string) {
	t.Helper()

	select {
	case <-w.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// shortWarmUpStartDelay shortens the delay the background warm-up waits for,
// so tests do not have to sleep for config.WarmUpStartDelay.
func shortWarmUpStartDelay(t *testing.T, d time.Duration) {
	t.Helper()

	old := warmUpStartDelay
	warmUpStartDelay = d
	t.Cleanup(func() { warmUpStartDelay = old })
}

// TestStartWarmUpDispatch covers the gating of the background warm-up: it runs
// exactly when the configuration allows it and never propagates its failure.
// Every assertion is event-based (the stub signals completion) so the test does
// not depend on scheduling delays, which the race detector inflates.
func TestStartWarmUpDispatch(t *testing.T) {
	tests := []struct {
		name       string
		disable    bool
		nilServer  bool
		err        error
		wantProbes int64
	}{
		{
			name:       "enabled by default",
			wantProbes: 1,
		},
		{
			name:       "disabled by config",
			disable:    true,
			wantProbes: 0,
		},
		{
			name:       "no socks server",
			nilServer:  true,
			wantProbes: 0,
		},
		{
			name:       "a failed warm-up is swallowed",
			err:        errors.New("probe failed"),
			wantProbes: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shortWarmUpStartDelay(t, 0)
			calls, done := stubWarmUp(t, tt.err)

			cfg := testConfig()
			cfg.Transport.DisableWarmUp = tt.disable

			core := &Core{Cfg: cfg}
			if !tt.nilServer {
				core.SocksServer = &proxy.Socks5Server{}
			}

			// Best-effort by contract: StartWarmUp never blocks or panics.
			core.StartWarmUp()

			if tt.wantProbes > 0 {
				done.waitProbe(t, "the warm-up probe")
			}
			if got := calls.Load(); got != tt.wantProbes {
				t.Fatalf("warm-up ran %d times, want %d", got, tt.wantProbes)
			}
		})
	}
}

// TestStartWarmUpWaitStartDelay verifies that the probe is postponed by
// config.WarmUpStartDelay: the host gets time to bring its network path up
// before a probe can fail for that reason alone.
func TestStartWarmUpWaitStartDelay(t *testing.T) {
	shortWarmUpStartDelay(t, 100*time.Millisecond)
	calls, done := stubWarmUp(t, nil)

	core := &Core{Cfg: testConfig(), SocksServer: &proxy.Socks5Server{}}
	core.StartWarmUp()

	if got := calls.Load(); got != 0 {
		t.Fatalf("warm-up probe fired before the start delay, ran %d times", got)
	}

	done.waitProbe(t, "the delayed warm-up probe")
	if got := calls.Load(); got != 1 {
		t.Fatalf("warm-up probe ran %d times, want 1", got)
	}
}

// TestStopCancelsPendingWarmUp verifies the shutdown path: a warm-up still
// waiting for its start delay is dropped by the cancel Stop performs, so a
// short-lived core never probes against a torn-down transport.
//
// The test calls the cancel path directly instead of Core.Stop: the warm-up
// cancel is the first thing Stop does, while the rest of Stop tears down
// live servers this bare Core does not own.
func TestStopCancelsPendingWarmUp(t *testing.T) {
	// Long enough that the probe can only fire if the cancel failed.
	shortWarmUpStartDelay(t, 5*time.Second)
	calls, _ := stubWarmUp(t, nil)

	core := &Core{Cfg: testConfig(), SocksServer: &proxy.Socks5Server{}}
	core.StartWarmUp()

	done := make(chan struct{})
	go func() {
		core.cancelWarmUp()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop blocked on the warm-up")
	}

	if got := calls.Load(); got != 0 {
		t.Fatalf("warm-up probe ran despite the cancel, ran %d times", got)
	}
	if left := warmUpCancelOf(core); left != nil {
		t.Fatal("the cancel did not clear the recorded warm-up cancel func")
	}
}

// warmUpCancelOf snapshots the cancel func of the dispatched warm-up.
func warmUpCancelOf(c *Core) context.CancelFunc {
	c.warmUpMu.Lock()
	defer c.warmUpMu.Unlock()
	return c.warmUpCancel
}

// TestStopCancelsInFlightWarmUp verifies that Stop also cancels a probe that
// already started: the warm-up context is done by the time Stop returns, so a
// transport that honours ctx stops instead of racing the closing core. Stop
// must not block on the probe either.
func TestStopCancelsInFlightWarmUp(t *testing.T) {
	shortWarmUpStartDelay(t, 0)
	calls, done := stubWarmUp(t, nil)

	core := &Core{Cfg: testConfig(), SocksServer: &proxy.Socks5Server{}}
	core.StartWarmUp()

	cancel := warmUpCancelOf(core)
	if cancel == nil {
		t.Fatal("StartWarmUp did not record a cancel func")
	}
	done.waitProbe(t, "the in-flight warm-up probe")
	if got := calls.Load(); got != 1 {
		t.Fatalf("warm-up probe ran %d times, want 1", got)
	}

	// Stop cancels the warm-up context and returns without waiting for the
	// probe that may still be in flight.
	stopped := make(chan struct{})
	go func() {
		core.cancelWarmUp()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop blocked on the in-flight warm-up")
	}

	if left := warmUpCancelOf(core); left != nil {
		t.Fatal("Stop did not clear the recorded warm-up cancel func")
	}
}

// TestResolveServerDomain covers the startup server-domain resolution with
// an injected prePopulateServerDomain so no real DNS query ever leaves the
// test. A failed resolution is a fatal error (the server is unreachable).
func TestResolveServerDomain(t *testing.T) {
	oldFn := prePopulateServerDomain
	oldTimeout := serverStartupResolveTimeout
	oldDelay := serverStartupRetryDelay
	t.Cleanup(func() {
		prePopulateServerDomain = oldFn
		serverStartupResolveTimeout = oldTimeout
		serverStartupRetryDelay = oldDelay
	})
	serverStartupResolveTimeout = 50 * time.Millisecond
	serverStartupRetryDelay = 0

	// A literal IP needs no resolution: skipped without touching the DNS.
	cfgIP := testConfig() // Address is 127.0.0.1
	attempts := 0
	prePopulateServerDomain = func(*proxy.Socks5Server, context.Context, string, []string, bool) error {
		attempts++
		return nil
	}
	c := &Core{}
	if err := c.resolveServerDomain(cfgIP); err != nil {
		t.Fatalf("IP address should not resolve: %v", err)
	}
	if attempts != 0 {
		t.Fatalf("IP address should not query DNS, got %d attempts", attempts)
	}

	// No default server: skipped.
	cfgNone := testConfig()
	cfgNone.Servers = nil
	c = &Core{}
	if err := c.resolveServerDomain(cfgNone); err != nil {
		t.Fatalf("no server should not resolve: %v", err)
	}

	// Non-TUN failure: a single bounded attempt, fatal error returned.
	cfgDomain := testConfig()
	cfgDomain.Servers[0].Address = "proxy.example.com"
	cfgDomain.Local.EnableTun2socks = false
	prePopulateServerDomain = func(*proxy.Socks5Server, context.Context, string, []string, bool) error {
		attempts++
		return errors.New("dns boom")
	}
	attempts = 0
	c = &Core{SocksServer: &proxy.Socks5Server{}}
	err := c.resolveServerDomain(cfgDomain)
	if err == nil {
		t.Fatal("expected error on resolution failure")
	}
	if !strings.Contains(err.Error(), "resolution failed") {
		t.Fatalf("unexpected error text: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("non-TUN should attempt once, got %d", attempts)
	}

	// TUN failure: retried 3 times (the pre-population is mandatory there).
	cfgTun := testConfig()
	cfgTun.Servers[0].Address = "proxy.example.com"
	cfgTun.Local.EnableTun2socks = true
	attempts = 0
	c = &Core{SocksServer: &proxy.Socks5Server{}}
	if err := c.resolveServerDomain(cfgTun); err == nil {
		t.Fatal("expected error on TUN resolution failure")
	}
	if attempts != 3 {
		t.Fatalf("TUN should attempt 3 times, got %d", attempts)
	}

	// Success: no error.
	prePopulateServerDomain = func(*proxy.Socks5Server, context.Context, string, []string, bool) error {
		attempts++
		return nil
	}
	attempts = 0
	c = &Core{SocksServer: &proxy.Socks5Server{}}
	if err := c.resolveServerDomain(cfgDomain); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected a single successful attempt, got %d", attempts)
	}

	// No DNS servers configured: reported as a resolution failure.
	oldDirect := config.DirectDNSServers
	config.DirectDNSServers = nil
	t.Cleanup(func() { config.DirectDNSServers = oldDirect })
	attempts = 0
	c = &Core{SocksServer: &proxy.Socks5Server{}}
	if err := c.resolveServerDomain(cfgDomain); err == nil {
		t.Fatal("expected error when no dns servers configured")
	}
	if attempts != 0 {
		t.Fatalf("no dns servers should short-circuit without attempts, got %d", attempts)
	}
}

// TestRunFailsOnServerDomainResolve verifies that a failed server-domain
// resolution aborts startup: Run returns a fatal error instead of starting
// the servers, because the proxy cannot work without it.
func TestRunFailsOnServerDomainResolve(t *testing.T) {
	oldFn := prePopulateServerDomain
	oldTimeout := serverStartupResolveTimeout
	oldDelay := serverStartupRetryDelay
	t.Cleanup(func() {
		prePopulateServerDomain = oldFn
		serverStartupResolveTimeout = oldTimeout
		serverStartupRetryDelay = oldDelay
	})
	serverStartupResolveTimeout = 50 * time.Millisecond
	serverStartupRetryDelay = 0

	cfg := testConfig()
	cfg.Servers[0].Address = "proxy.example.com"
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = 0

	prePopulateServerDomain = func(*proxy.Socks5Server, context.Context, string, []string, bool) error {
		return errors.New("dns boom")
	}

	core, err := Run(cfg)
	if err == nil {
		core.Stop()
		t.Fatal("expected Run to fail when the server domain cannot resolve")
	}
	if !strings.Contains(err.Error(), "resolution failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
