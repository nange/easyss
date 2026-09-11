package runner

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/config"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/util"
)

// startProbeServer starts a local TLS server that speaks HTTP/2 and serves
// /v3/probe with the payload a real server pre-generates, mirroring how
// transport/http2 confirms a warmed connection (200 + octet-stream + the
// exact payload size). It returns the server URL and the PEM path of the
// server's self-signed certificate, so a client can be pointed at it without
// any real network.
func startProbeServer(t *testing.T) (srvURL, caPath string, probes *atomic.Int64) {
	t.Helper()

	probes = &atomic.Int64{}
	payload := make([]byte, sharedconfig.ProbePayloadSize)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != sharedconfig.EndpointProbe {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		probes.Add(1)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	caPath = filepath.Join(t.TempDir(), "ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("write test CA: %v", err)
	}

	return srv.URL, caPath, probes
}

// warmUpConfig points a client config at the local probe server with warm-up
// left at its default (enabled).
func warmUpConfig(t *testing.T, srvURL, caPath string) *config.ClientConfig {
	t.Helper()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srvURL, "https://"))
	if err != nil {
		t.Fatalf("parse test server URL %q: %v", srvURL, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse test server port %q: %v", portStr, err)
	}
	if !util.IsIP(host) {
		// A literal IP keeps resolveServerDomain out of the test: it skips
		// literal IPs, so no real DNS query is issued.
		t.Fatalf("test server host %q is not an IP", host)
	}

	cfg := testConfig()
	cfg.Servers[0].Address = host
	cfg.Servers[0].Port = port
	cfg.Servers[0].CAPath = caPath
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = 0
	cfg.Routing.IPV6Rule = "disable"
	return cfg
}

// TestRunWarmsUpOverRealTransport is the end-to-end check of the runner-owned
// warm-up: with the default configuration the core must, after starting, probe
// both scheduling pools over its real HTTP/2 transport without blocking Run.
func TestRunWarmsUpOverRealTransport(t *testing.T) {
	srvURL, caPath, probes := startProbeServer(t)
	cfg := warmUpConfig(t, srvURL, caPath)

	start := time.Now()
	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(core.Stop)

	// Run dispatches the warm-up and returns: startup must not wait for it.
	if elapsed := time.Since(start); elapsed >= sharedconfig.WarmUpStartDelay {
		t.Fatalf("Run took %v, so it waited for the warm-up instead of dispatching it", elapsed)
	}

	// Both pools (priority + bulk) are primed, each with its own probe.
	deadline := time.Now().Add(sharedconfig.WarmUpTimeout + time.Second)
	for time.Now().Before(deadline) && probes.Load() < 2 {
		time.Sleep(10 * time.Millisecond)
	}

	if got := probes.Load(); got < 2 {
		t.Fatalf("got %d probe requests, want 2 (one per scheduling pool)", got)
	}
}

// TestRunDoesNotWarmUpWhenDisabled verifies the configuration switch: with
// transport.disable_warm_up the core never probes the server.
func TestRunDoesNotWarmUpWhenDisabled(t *testing.T) {
	srvURL, caPath, probes := startProbeServer(t)
	cfg := warmUpConfig(t, srvURL, caPath)
	cfg.Transport.DisableWarmUp = true

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(core.Stop)

	// Wait past the moment the warm-up would have probed.
	time.Sleep(sharedconfig.WarmUpStartDelay + 300*time.Millisecond)

	if got := probes.Load(); got != 0 {
		t.Fatalf("got %d probe requests with the warm-up disabled, want 0", got)
	}
}

// TestRunWarmUpSkippedWithoutSocksServer verifies the socks_port = 0 shape:
// there is no local SOCKS5 proxy to warm, so the core skips the warm-up
// instead of failing or probing anyway.
func TestRunWarmUpSkippedWithoutSocksServer(t *testing.T) {
	srvURL, caPath, probes := startProbeServer(t)
	cfg := warmUpConfig(t, srvURL, caPath)
	cfg.Local.SocksPort = 0
	cfg.Local.HTTPPort = 0

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(core.Stop)

	time.Sleep(sharedconfig.WarmUpStartDelay + 200*time.Millisecond)

	if got := probes.Load(); got != 0 {
		t.Fatalf("got %d probe requests without a SOCKS5 server, want 0", got)
	}
}
