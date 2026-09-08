package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTunTestServer builds an HTTPProxyServer with proxy credentials
// configured, mimicking a real deployment where the /tun endpoint must be
// reachable by the unauthenticated TUN helper over loopback.
func newTunTestServer(t *testing.T) *HTTPProxyServer {
	t.Helper()
	s, err := NewHTTPProxyServer("127.0.0.1:0", "127.0.0.1:4080", "user", "pass", 5*time.Second, nil, nil, 0, nil)
	if err != nil {
		t.Fatalf("NewHTTPProxyServer: %v", err)
	}
	return s
}

func testTunConfig() *TunConfig {
	return &TunConfig{
		Socks5Addr:   "socks5://127.0.0.1:4080",
		DNSAddr:      "127.0.0.1",
		Device:       "utun9",
		TunIP:        "198.18.0.1",
		TunGW:        "198.18.0.1",
		TunMask:      "255.255.0.0",
		LocalGateway: "192.168.1.1",
		MTU:          1500,
	}
}

// TestTunEndpointServedWithoutProxyAuth verifies the TUN helper can fetch
// GET /tun without proxy credentials even when auth is configured (the
// helper has no way to obtain them).
func TestTunEndpointServedWithoutProxyAuth(t *testing.T) {
	s := newTunTestServer(t)
	s.SetTunConfig(testTunConfig())

	req := httptest.NewRequest(http.MethodGet, "/tun", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /tun from loopback without proxy auth: code = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got TunConfig
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode tun config: %v", err)
	}
	if got.Device != "utun9" || got.Socks5Addr != "socks5://127.0.0.1:4080" {
		t.Fatalf("unexpected tun config: %+v", got)
	}
}

// TestTunEndpointRejectsNonLoopbackSource verifies /tun is never served to
// non-loopback clients (protects the config when bind_all is enabled).
func TestTunEndpointRejectsNonLoopbackSource(t *testing.T) {
	s := newTunTestServer(t)
	s.SetTunConfig(testTunConfig())

	req := httptest.NewRequest(http.MethodGet, "/tun", nil)
	req.RemoteAddr = "192.168.1.100:5555"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /tun from non-loopback source: code = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestTunEndpointNotConfiguredReturns503 verifies the helper's retry loop
// still sees 503 when the parent has not registered a TUN config yet.
func TestTunEndpointNotConfiguredReturns503(t *testing.T) {
	s := newTunTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/tun", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /tun before SetTunConfig: code = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

// TestProxyAuthStillRequiredForProxyRequests verifies the auth exemption is
// scoped to /tun only: ordinary proxy requests still require credentials.
func TestProxyAuthStillRequiredForProxyRequests(t *testing.T) {
	s := newTunTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("proxy request without credentials: code = %d, want %d", rec.Code, http.StatusProxyAuthRequired)
	}
}
