package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTunTestServer 构建一个配置了代理凭据的 HTTPProxyServer，模拟真实部署场景：
// 未认证的 TUN 助手必须能通过回环地址访问 /tun 端点。
func newTunTestServer(t *testing.T) *HTTPProxyServer {
	t.Helper()
	s, err := NewHTTPProxyServer(HTTPProxyOptions{
		ListenAddr: "127.0.0.1:0",
		SocksAddr:  "127.0.0.1:4080",
		Username:   "user",
		Password:   "pass",
		Timeout:    5 * time.Second,
	})
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

// TestTunEndpointServedWithoutProxyAuth 验证即使配置了认证，TUN 助手也能不带任何
// 代理凭据获取 GET /tun（助手没有办法获得这些凭据）。
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

// TestTunEndpointRejectsNonLoopbackSource 验证 /tun 绝不会提供给非回环客户端
// （在启用 bind_all 时保护配置）。
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

// TestTunEndpointNotConfiguredReturns503 验证当父进程尚未注册 TUN 配置时，
// 助手的重试循环仍然会看到 503。
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

// TestProxyAuthStillRequiredForProxyRequests 验证认证豁免仅限 /tun：
// 普通的代理请求仍然需要凭据。
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
