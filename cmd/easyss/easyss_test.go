package main_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	testServerAddr     = "127.0.0.1"
	testPassword       = "test-pass"
	testServerPort     = 19999
	testSocks5Port     = 14567
	testHTTPPort       = 15567
	testCloseWritePort = 18888
	testTargetPort     = 17777
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
		for attempt := 0; attempt < 2; attempt++ {
			if attempt > 0 {
				time.Sleep(2 * time.Second)
			}
			resp, err := client.Get(url)
			if err != nil {
				t.Logf("GET %s attempt %d: %v", url, attempt+1, err)
				continue
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
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

// waitForServer polls until the server is accepting connections
func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("server did not start in time")
}

// waitForListener polls until a listener is accepting connections
func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("listener did not start in time")
}

// startLocalTargetServer starts a basic HTTP server for testing direct/local connections
func startLocalTargetServer(t *testing.T) func() {
	t.Helper()
	addr := testServerAddr + ":" + strconv.Itoa(testTargetPort)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "hello-from-target: %s", r.URL.Path)
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		_ = srv.ListenAndServe()
	}()

	waitForListener(t, addr)

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(ctx) //nolint:errcheck
	}
}

// startTCPEchoServer starts a TCP echo server for CloseWrite testing
func startTCPEchoServer(t *testing.T) func() {
	t.Helper()
	addr := testServerAddr + ":" + strconv.Itoa(testCloseWritePort)

	lis, err := net.Listen("tcp", addr)
	require.NoError(t, err)

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
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

	waitForListener(t, addr)

	return func() { lis.Close() }
}

type testHarness struct {
	tempDir  string
	certPath string
	keyPath  string
	caPath   string
	server   *server.Server
	cli      *client.Client

	socksServer *proxy.Socks5Server
	httpProxy   *proxy.HTTPProxyServer

	targetCleanup func()
	echoCleanup   func()

	cleanupOnce sync.Once
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	h := &testHarness{}

	// Write cert files
	h.tempDir = t.TempDir()
	h.certPath = filepath.Join(h.tempDir, "cert.pem")
	h.keyPath = filepath.Join(h.tempDir, "key.pem")
	h.caPath = filepath.Join(h.tempDir, "ca.pem")

	require.NoError(t, os.WriteFile(h.certPath, []byte(ServerCert), 0644))
	require.NoError(t, os.WriteFile(h.keyPath, []byte(ServerKey), 0644))
	require.NoError(t, os.WriteFile(h.caPath, []byte(CACert), 0644))

	// Start local target servers
	h.targetCleanup = startLocalTargetServer(t)
	h.echoCleanup = startTCPEchoServer(t)

	// Create server config
	serverCfg := &serverconfig.ServerConfig{
		Listen:   testServerAddr + ":" + strconv.Itoa(testServerPort),
		Password: testPassword,
		CertPath: h.certPath,
		KeyPath:  h.keyPath,
		Timeout:  30,
	}

	srv, err := server.New(serverCfg)
	require.NoError(t, err)
	h.server = srv

	// Start server in background
	go func() {
		if err := srv.Start(); err != nil {
			t.Logf("[SERVER] exited: %v", err)
		}
	}()

	waitForServer(t, fmt.Sprintf("%s:%d", testServerAddr, testServerPort))

	// Create client config
	clientCfg := &clientconfig.ClientConfig{
		ConfigVersion: 3,
		Servers: []*clientconfig.ServerProfile{
			{
				Address:  testServerAddr,
				Port:     testServerPort,
				Password: testPassword,
				Method:   "aes-256-gcm",
				SNI:      testServerAddr,
				CAPath:   h.caPath,
				Default:  true,
			},
		},
		Local: clientconfig.LocalConfig{
			SocksPort: testSocks5Port,
			HTTPPort:  testHTTPPort,
		},
		Routing: clientconfig.RoutingConfig{
			ProxyRule: "proxy",
			IPV6Rule:  "disable",
		},
		Transport: clientconfig.TransportConfig{
			Protocol:       "h2",
			EndpointPrefix: "/v3",
			ConnCountMax:   4,
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

	// Determine encryption method
	method := protocol.MethodFromString("aes-256-gcm")

	// Create stream handler
	timeout := clientCfg.TimeoutDuration()
	streamIdleTimeout := 10 * timeout
	udpIdleTimeout := 2 * timeout
	shaperCfg := shaper.Config{
		BatchWindowMS: clientCfg.Shaper.BatchWindowMS,
		Cover: shaper.CoverConfig{
			BudgetRatio: clientCfg.Shaper.CoverBudgetRatio,
		},
	}
	handler := proxy.NewStreamHandler(cli.Transport(), cli.MasterKey(), shaperCfg, streamIdleTimeout)

	// Start SOCKS5 proxy
	socksAddr := testServerAddr + ":" + strconv.Itoa(testSocks5Port)
	socksServer, err := proxy.NewSocks5Server(socksAddr, "", "", handler, cli.Router(), method, true, udpIdleTimeout, cli.DialContext)
	require.NoError(t, err)
	h.socksServer = socksServer

	go func() {
		if err := socksServer.Start(); err != nil {
			t.Logf("[SOCKS5] exited: %v", err)
		}
	}()
	waitForListener(t, socksAddr)

	// Start HTTP proxy
	httpAddr := testServerAddr + ":" + strconv.Itoa(testHTTPPort)
	socksProxyAddr := testServerAddr + ":" + strconv.Itoa(testSocks5Port)
	httpProxy, err := proxy.NewHTTPProxyServer(httpAddr, socksProxyAddr, "", "", timeout, handler, cli.Router(), method, cli.DialContext)
	require.NoError(t, err)
	h.httpProxy = httpProxy

	go func() {
		if err := httpProxy.Start(); err != nil {
			t.Logf("[HTTP-PROXY] exited: %v", err)
		}
	}()
	waitForListener(t, httpAddr)

	return h
}

func (h *testHarness) Close() {
	h.cleanupOnce.Do(func() {
		if h.socksServer != nil {
			h.socksServer.Close() //nolint:errcheck
		}
		if h.httpProxy != nil {
			h.httpProxy.Close() //nolint:errcheck
		}
		if h.cli != nil {
			h.cli.Close() //nolint:errcheck
		}
		if h.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			h.server.Shutdown(ctx) //nolint:errcheck
		}
		if h.targetCleanup != nil {
			h.targetCleanup()
		}
		if h.echoCleanup != nil {
			h.echoCleanup()
		}
	})
}

// TestV3Integration_Socks5Proxy tests HTTP requests through the SOCKS5 proxy via the v3 tunnel
func TestV3Integration_Socks5Proxy(t *testing.T) {
	h := newTestHarness(t)
	defer h.Close()

	socksAddr := testServerAddr + ":" + strconv.Itoa(testSocks5Port)
	sc, err := socks5.NewClient(socksAddr, "", "", 0, 0)
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
	defer h.Close()

	proxyAddr := fmt.Sprintf("http://%s:%d", testServerAddr, testHTTPPort)
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
	defer h.Close()

	socksAddr := testServerAddr + ":" + strconv.Itoa(testSocks5Port)
	sc, err := socks5.NewClient(socksAddr, "", "", 0, 0)
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

	targetURL := fmt.Sprintf("http://%s:%d/direct-test", testServerAddr, testTargetPort)
	resp, err := client.Get(targetURL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "hello-from-target: /direct-test")
}

// TestV3Integration_CloseWrite tests TCP half-close through the SOCKS5 proxy
func TestV3Integration_CloseWrite(t *testing.T) {
	h := newTestHarness(t)
	defer h.Close()

	msg := "hello-closewrite"

	socksAddr := testServerAddr + ":" + strconv.Itoa(testSocks5Port)
	sc, err := socks5.NewClient(socksAddr, "", "", 30, 30)
	require.NoError(t, err)

	conn, err := sc.Dial("tcp", testServerAddr+":"+strconv.Itoa(testCloseWritePort))
	require.NoError(t, err)
	defer conn.Close()

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
	defer h.Close()

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
	assert.Equal(t, 2080, cfg.Local.SocksPort)
	assert.Equal(t, 3080, cfg.Local.HTTPPort)
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
