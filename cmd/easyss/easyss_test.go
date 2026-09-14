package main_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/txthinking/socks5"

	"github.com/nange/easyss/v3/client"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/router"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	server "github.com/nange/easyss/v3/server"
	serverconfig "github.com/nange/easyss/v3/server/config"
	"github.com/nange/easyss/v3/shaper"
)

const (
	CACert = `-----BEGIN CERTIFICATE-----
MIIB1DCCAXqgAwIBAgIULPyfQyUssIDTxsGLzQJx6w5rbukwCgYIKoZIzj0EAwIw
SDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMRQwEgYDVQQDEwtlYXN5LWNhLm5ldDAeFw0yNDAyMTgwNzA1MDBaFw0yOTAy
MTYwNzA1MDBaMEgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMN
U2FuIEZyYW5jaXNjbzEUMBIGA1UEAxMLZWFzeS1jYS5uZXQwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAT71NO1p1yANOG7AkEe1bQvcQp6fNgRRqvwrC/cIGp6bDqt
H3klE8D22g5upORqkETrqlKeqi0UxflAUD9RSh7Ro0IwQDAOBgNVHQ8BAf8EBAMC
AQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU8pqT0wmFdRQ6gxX+ZWAWhMon
fIQwCgYIKoZIzj0EAwIDSAAwRQIhAO3ZLMAh8nlR2cJbecUZJ51GbBbLny5CdcN7
CbTHmkaiAiB+LABnNKD+O0P+UPidt+nBpo+2u1/W7wtQvKJcFVl+mQ==
-----END CERTIFICATE-----
`
	ServerCert = `-----BEGIN CERTIFICATE-----
MIICIDCCAcagAwIBAgIUPMWIWsDwAl4fIpDSHDbPAS/YX2MwCgYIKoZIzj0EAwIw
SDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMRQwEgYDVQQDEwtlYXN5LWNhLm5ldDAgFw0yNDAyMTgwNzA3MDBaGA8yMTI0
MDEyNTA3MDcwMFowTDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMRgwFgYDVQQDEw9lYXN5LXNlcnZlci5uZXQwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATaBuIN8NmDmSMmSpXbNp2pzqIjTtyvccgEGTdx
TbtWF2YvqqwmQY/fPDyRDp1hCq2toD1wCEjCXOJx5BaF1n8Wo4GHMIGEMA4GA1Ud
DwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0G
A1UdDgQWBBSnOwxAIjDEYPp88Ooed4HWL9r8bTAfBgNVHSMEGDAWgBTympPTCYV1
FDqDFf5lYBaEyid8hDAPBgNVHREECDAGhwR/AAABMAoGCCqGSM49BAMCA0gAMEUC
IGphTgfgOgRRGIqDX/ByZx33QUh6P+nRSPyMPLV24nDGAiEAl0I45LBWXopCzDLD
ftJgQof/GMr8+pMLn0UM/Xv5xec=
-----END CERTIFICATE-----
`
	ServerKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIO8NZoPnbSD3NL9PmL9zMz/OUvFuwYVGzzicctyWbf57oAoGCCqGSM49
AwEHoUQDQgAE2gbiDfDZg5kjJkqV2zadqc6iI07cr3HIBBk3cU27VhdmL6qsJkGP
3zw8kQ6dYQqtraA9cAhIwlziceQWhdZ/Fg==
-----END EC PRIVATE KEY-----
`
)

const (
	testServerAddr = "127.0.0.1"
	testPassword   = "test-pass"

	// readinessTimeout bounds how long the harness waits for an
	// asynchronously started server to accept connections. A start failure is
	// reported through the error channel right away, so this only covers
	// scheduling delay under load (measured: ~0.2s plain, ~0.7s with -race).
	readinessTimeout = 15 * time.Second
)

// testExternalURLs are used for testing the full proxy tunnel.
// Multiple URLs for fallback in case one is temporarily unavailable.
var testExternalURLs = []string{
	"http://www.example.com",
	"https://www.baidu.com",
	"http://httpbin.org/get",
}

// fetchExternalURL tries to GET url via client, with retries across fallback URLs
func fetchExternalURL(t *testing.T, client *http.Client) (body []byte, status int) {
	t.Helper()
	for _, url := range testExternalURLs {
		for attempt := range 2 {
			if attempt > 0 {
				time.Sleep(2 * time.Second)
			}
			resp, err := client.Get(url)
			if err != nil {
				t.Logf("GET %s attempt %d: %v", url, attempt+1, err)
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close() //nolint:errcheck
			if err != nil {
				t.Logf("read body %s attempt %d: %v", url, attempt+1, err)
				continue
			}
			if resp.StatusCode == http.StatusOK {
				return body, resp.StatusCode
			}
			t.Logf("GET %s attempt %d: status=%d body=%d bytes", url, attempt+1, resp.StatusCode, len(body))
		}
	}
	t.Fatal("all external URLs failed")
	return nil, 0
}

// loopbackAddr formats a 127.0.0.1 address for a chosen port.
func loopbackAddr(port int) string {
	return testServerAddr + ":" + strconv.Itoa(port)
}

// freeTCPPort returns a loopback TCP port that is currently free. Choosing a
// port per test keeps concurrent runs of this package (a second terminal, an
// IDE test run, another checkout) from stealing each other's listeners.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", testServerAddr+":0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// freeSocks5Port returns a loopback port that is free on TCP and UDP both:
// the txthinking/socks5 server binds a TCP listener and a UDP socket on the
// same address, so a port free on TCP alone still fails to start.
func freeSocks5Port(t *testing.T) int {
	t.Helper()
	for range 20 {
		port := freeTCPPort(t)
		pc, err := net.ListenPacket("udp", loopbackAddr(port))
		if err != nil {
			continue
		}
		require.NoError(t, pc.Close())
		return port
	}
	t.Fatal("no loopback port free on both tcp and udp")
	return 0
}

// waitForReady polls addr until it accepts a TCP connection, so the harness
// only continues once an asynchronously started server really listens. A start
// failure published on startErr aborts immediately with that error: waiting
// out the deadline instead would disguise "address already in use" (or any
// other start failure) as a plain readiness timeout, and a foreign process
// holding the port would even be mistaken for the server under test.
func waitForReady(what, addr string, startErr <-chan error, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		select {
		case err := <-startErr:
			return fmt.Errorf("%s (%s) failed to start: %w", what, addr, err)
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close() //nolint:errcheck
			return nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return fmt.Errorf("%s (%s) did not accept connections within %s: %w", what, addr, timeout, lastErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startLocalTargetServer starts a basic HTTP server for testing direct/local
// connections. It returns the kernel-chosen address it listens on and a
// cleanup that shuts it down. The listener is bound here instead of inside
// Serve, so a busy port fails the test immediately and nothing has to be
// polled before the address is usable.
func startLocalTargetServer(t *testing.T) (string, func()) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "hello-from-target: %s", r.URL.Path) //nolint:errcheck
	})

	lis, err := net.Listen("tcp", testServerAddr+":0")
	require.NoError(t, err)

	srv := &http.Server{Handler: mux}
	go func() {
		_ = srv.Serve(lis)
	}()

	return lis.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(ctx) //nolint:errcheck
	}
}

// startTCPEchoServer starts a TCP echo server for CloseWrite testing. Like the
// target server it binds its own ephemeral port and returns it.
func startTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", testServerAddr+":0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck
				buf := make([]byte, 1024)
				for {
					nr, err := c.Read(buf)
					if err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
					if _, err := c.Write(buf[:nr]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return lis.Addr().String(), func() { _ = lis.Close() }
}

type testHarness struct {
	tempDir  string
	certPath string
	keyPath  string
	caPath   string

	serverAddr string
	socksAddr  string
	httpAddr   string
	targetAddr string
	echoAddr   string

	cli *client.Client

	// closers holds the teardown of every component that started, in startup
	// order; Close runs them in reverse. The socks5 proxy is only appended
	// after its Start reported success: txthinking/socks5 registers its TCP
	// runner before binding the UDP socket on the same address, so once Start
	// has returned an error its Shutdown would block forever on the runner
	// group's never-closed done channel.
	closers []func()

	cleanupOnce sync.Once
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	h := &testHarness{}

	// Every listener gets a kernel-chosen port: two runs of this package on
	// one machine must not fight over listeners, and a taken port has to fail
	// loudly instead of being mistaken for a merely slow start.
	serverPort := freeTCPPort(t)
	socksPort := freeSocks5Port(t)
	httpPort := freeTCPPort(t)
	h.serverAddr = loopbackAddr(serverPort)
	h.socksAddr = loopbackAddr(socksPort)
	h.httpAddr = loopbackAddr(httpPort)

	// Write cert files
	h.tempDir = t.TempDir()
	h.certPath = filepath.Join(h.tempDir, "cert.pem")
	h.keyPath = filepath.Join(h.tempDir, "key.pem")
	h.caPath = filepath.Join(h.tempDir, "ca.pem")

	require.NoError(t, os.WriteFile(h.certPath, []byte(ServerCert), 0644))
	require.NoError(t, os.WriteFile(h.keyPath, []byte(ServerKey), 0644))
	require.NoError(t, os.WriteFile(h.caPath, []byte(CACert), 0644))

	// Start local target servers
	targetAddr, targetCleanup := startLocalTargetServer(t)
	t.Cleanup(targetCleanup)
	h.targetAddr = targetAddr

	echoAddr, echoCleanup := startTCPEchoServer(t)
	t.Cleanup(echoCleanup)
	h.echoAddr = echoAddr

	// Registered after the local targets so it runs before their cleanups
	// (t.Cleanup is LIFO): every component started below then tears itself
	// down even when a t.Fatal unwinds the test without running its defers.
	t.Cleanup(h.Close)

	// Create server config
	serverCfg := &serverconfig.ServerConfig{
		Listen:   h.serverAddr,
		Password: testPassword,
		CertPath: h.certPath,
		KeyPath:  h.keyPath,
		Timeout:  30,
	}

	srv, err := server.New(serverCfg)
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start()
	}()
	h.closers = append(h.closers, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx) //nolint:errcheck
	})
	require.NoError(t, waitForReady("v3 server", h.serverAddr, serverErr, readinessTimeout))

	// Create client config
	clientCfg := &clientconfig.ClientConfig{
		ConfigVersion: 3,
		Servers: []*clientconfig.ServerProfile{
			{
				Address:  testServerAddr,
				Port:     serverPort,
				Password: testPassword,
				Method:   "aes-256-gcm",
				SNI:      testServerAddr,
				CAPath:   h.caPath,
				Default:  true,
			},
		},
		Local: clientconfig.LocalConfig{
			SocksPort: socksPort,
			HTTPPort:  httpPort,
		},
		Routing: clientconfig.RoutingConfig{
			ProxyRule: "proxy",
			IPV6Rule:  "disable",
		},
		Transport: clientconfig.TransportConfig{
			Protocol:     "h2",
			ConnCountMax: 4,
		},
		Shaper: clientconfig.ShaperConfig{
			BatchWindowMS: 3,
		},
		Log: clientconfig.LogConfig{
			Level: "warn",
		},
		Timeout: 30,
	}

	cli, err := client.New(clientCfg)
	require.NoError(t, err)
	h.cli = cli
	h.closers = append(h.closers, func() { _ = cli.Close() })

	// Determine encryption method
	method := protocol.MethodFromString("aes-256-gcm")

	// Create stream handler
	timeout := clientCfg.TimeoutDuration()
	streamIdleTimeout := sharedconfig.StreamIdleTimeout(timeout)
	udpIdleTimeout := sharedconfig.UDPIdleTimeout(timeout)
	dialTimeout := sharedconfig.DialTimeout(timeout)
	shaperCfg := shaper.Config{
		BatchWindowMS: clientCfg.Shaper.BatchWindowMS,
		Cover: shaper.CoverConfig{
			BudgetRatio: clientCfg.Shaper.CoverBudgetRatio,
		},
	}
	handler := proxy.NewStreamHandler(cli.Transport(), cli.MasterKey(), shaperCfg, streamIdleTimeout)

	// Start SOCKS5 proxy
	socksServer, err := proxy.NewSocks5Server(h.socksAddr, "", "", handler, cli.Router(), "", method, true, dialTimeout, udpIdleTimeout, timeout/3, streamIdleTimeout, cli.DialContext)
	require.NoError(t, err)

	socksErr := make(chan error, 1)
	go func() {
		socksErr <- socksServer.Start()
	}()
	require.NoError(t, waitForReady("socks5 proxy", h.socksAddr, socksErr, readinessTimeout))
	// Appended only now: a Start that failed inside socks5 leaves a runner
	// group that Shutdown can never finish (see the closers field comment).
	h.closers = append(h.closers, func() { _ = socksServer.Close() })

	// Start HTTP proxy
	httpProxy, err := proxy.NewHTTPProxyServer(h.httpAddr, h.socksAddr, "", "", timeout, handler, cli.Router(), method, cli.DialContext)
	require.NoError(t, err)

	httpErr := make(chan error, 1)
	go func() {
		httpErr <- httpProxy.Start()
	}()
	h.closers = append(h.closers, func() { _ = httpProxy.Close() })
	require.NoError(t, waitForReady("http proxy", h.httpAddr, httpErr, readinessTimeout))

	return h
}

func (h *testHarness) Close() {
	h.cleanupOnce.Do(func() {
		// Reverse startup order: proxies first, then the client, then the
		// server the client was talking to.
		for _, closer := range slices.Backward(h.closers) {
			closer()
		}
	})
}

// TestV3Integration_Socks5Proxy tests HTTP requests through the SOCKS5 proxy via the v3 tunnel
func TestV3Integration_Socks5Proxy(t *testing.T) {
	h := newTestHarness(t)

	sc, err := socks5.NewClient(h.socksAddr, "", "", 0, 0)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := sc.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				_ = conn.SetDeadline(time.Time{})
				return conn, nil
			},
			TLSHandshakeTimeout: 30 * time.Second,
			MaxConnsPerHost:     1,
		},
		Timeout: 60 * time.Second,
	}

	body, status := fetchExternalURL(t, client)
	assert.Equal(t, http.StatusOK, status)
	assert.Greater(t, len(body), 100)
	t.Logf("SOCKS5 proxy response: %d bytes", len(body))
}

// TestV3Integration_HTTPProxy tests HTTP requests through the HTTP proxy via the v3 tunnel
func TestV3Integration_HTTPProxy(t *testing.T) {
	h := newTestHarness(t)

	proxyAddr := "http://" + h.httpAddr
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(proxyAddr)
			},
			TLSHandshakeTimeout: 30 * time.Second,
			MaxConnsPerHost:     1,
		},
		Timeout: 60 * time.Second,
	}

	body, status := fetchExternalURL(t, client)
	assert.Equal(t, http.StatusOK, status)
	assert.Greater(t, len(body), 100)
	t.Logf("HTTP proxy response: %d bytes", len(body))
}

// TestV3Integration_LocalDirect tests that local (LAN) connections go direct
func TestV3Integration_LocalDirect(t *testing.T) {
	h := newTestHarness(t)

	sc, err := socks5.NewClient(h.socksAddr, "", "", 0, 0)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := sc.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				_ = conn.SetDeadline(time.Time{})
				return conn, nil
			},
			MaxConnsPerHost: 1,
		},
		Timeout: 30 * time.Second,
	}

	targetURL := "http://" + h.targetAddr + "/direct-test"
	resp, err := client.Get(targetURL)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "hello-from-target: /direct-test")
}

// TestV3Integration_CloseWrite tests TCP half-close through the SOCKS5 proxy
func TestV3Integration_CloseWrite(t *testing.T) {
	h := newTestHarness(t)

	msg := "hello-closewrite"

	sc, err := socks5.NewClient(h.socksAddr, "", "", 30, 30)
	require.NoError(t, err)

	conn, err := sc.Dial("tcp", h.echoAddr)
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	// Clear any deadline set by SOCKS5 negotiation
	_ = conn.SetDeadline(time.Time{})

	// The socks5.Client wraps the real TCP connection; extract it for CloseWrite
	socksClient, ok := conn.(*socks5.Client)
	require.True(t, ok, "expected *socks5.Client from SOCKS5 dial")
	tcpConn, ok := socksClient.TCPConn.(*net.TCPConn)
	require.True(t, ok, "expected *net.TCPConn as underlying connection")

	// Send message
	_, err = tcpConn.Write([]byte(msg))
	require.NoError(t, err)

	// Close write side (half-close)
	err = tcpConn.CloseWrite()
	require.NoError(t, err)

	// Read response
	buf := make([]byte, 1024)
	nr, err := tcpConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, msg, string(buf[:nr]))
}

// TestV3Integration_Router tests that router properly classifies hosts
func TestV3Integration_Router(t *testing.T) {
	h := newTestHarness(t)

	rt := h.cli.Router()

	// With proxy_rule=proxy, all non-LAN hosts should be proxy
	// LAN hosts always go direct regardless of rule
	assert.Equal(t, router.HostRuleDirect, rt.MatchHostRule("127.0.0.1"))
	assert.Equal(t, router.HostRuleDirect, rt.MatchHostRule("localhost"))
	assert.Equal(t, router.HostRuleProxy, rt.MatchHostRule("google.com"))
	assert.Equal(t, router.HostRuleProxy, rt.MatchHostRule("baidu.com"))
	assert.Equal(t, router.HostRuleProxy, rt.MatchHostRule("example.com"))

	// Switch to auto rule
	rt.SetProxyRule(router.ProxyRuleAuto)

	// google.com should be proxied (foreign)
	assert.Equal(t, router.HostRuleProxy, rt.MatchHostRule("google.com"))

	// baidu.com should be direct (Chinese)
	assert.Equal(t, router.HostRuleDirect, rt.MatchHostRule("baidu.com"))

	// LAN hosts still direct
	assert.Equal(t, router.HostRuleDirect, rt.MatchHostRule("127.0.0.1"))
}

// TestV3Integration_ConfigDefaults tests that config defaults are properly applied
func TestV3Integration_ConfigDefaults(t *testing.T) {
	cfg := clientconfig.DefaultConfig()

	assert.Equal(t, 3, cfg.ConfigVersion)
	assert.Equal(t, 4080, cfg.Local.SocksPort)
	assert.Equal(t, 5080, cfg.Local.HTTPPort)
	assert.Equal(t, "auto", cfg.Routing.ProxyRule)
	assert.Equal(t, "auto", cfg.Routing.IPV6Rule)
	assert.Equal(t, 30, cfg.Timeout)
	assert.Equal(t, "info", cfg.Log.Level)

	// Clone should produce equivalent config
	clone := cfg.Clone()
	assert.Equal(t, cfg.Local.SocksPort, clone.Local.SocksPort)

	// DefaultServer returns nil when no servers configured
	assert.Nil(t, cfg.DefaultServer())
	assert.Equal(t, "", cfg.ServerURL())
}

// TestFreeSocks5PortIsFreeOnTCPAndUDP pins the reason the socks5 port is not
// picked with freeTCPPort: the txthinking/socks5 server binds TCP and UDP on
// the same address, so a port free on TCP alone still fails to start.
func TestFreeSocks5PortIsFreeOnTCPAndUDP(t *testing.T) {
	port := freeSocks5Port(t)

	l, err := net.Listen("tcp", loopbackAddr(port))
	require.NoError(t, err)
	pc, err := net.ListenPacket("udp", loopbackAddr(port))
	require.NoError(t, err)

	require.NoError(t, pc.Close())
	require.NoError(t, l.Close())
}

// TestWaitForReadyReportsStartError pins the fail-fast contract: a server that
// failed to start must be reported with its real error, not disguised as a
// readiness timeout.
func TestWaitForReadyReportsStartError(t *testing.T) {
	addr := loopbackAddr(freeTCPPort(t))
	startErr := make(chan error, 1)
	startErr <- errors.New("listen udp " + addr + ": bind: address already in use")

	start := time.Now()
	err := waitForReady("socks5 proxy", addr, startErr, 30*time.Second)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "socks5 proxy")
	assert.Contains(t, err.Error(), "bind: address already in use")
	assert.Less(t, time.Since(start), time.Second, "a start error must abort the wait immediately")
}

// TestWaitForReadyTimesOut covers the remaining case: nothing listening and no
// start error to report.
func TestWaitForReadyTimesOut(t *testing.T) {
	addr := loopbackAddr(freeTCPPort(t))

	err := waitForReady("http proxy", addr, make(chan error), 300*time.Millisecond)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "http proxy")
	assert.Contains(t, err.Error(), "did not accept connections")
}
