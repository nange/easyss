package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/shaper"
)

// 控制端点（/tun、/stats）在 bind_all 时也不能暴露到网络上。
func TestControlEndpointsRejectNonLoopback(t *testing.T) {
	s := &HTTPProxyServer{}
	for _, path := range []string{"/stats", "/tun"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.RemoteAddr = "203.0.113.9:4321"
		w := httptest.NewRecorder()

		s.ServeHTTP(w, r)

		if w.Code != http.StatusForbidden {
			t.Errorf("%s from a non-loopback peer = %d, want %d", path, w.Code, http.StatusForbidden)
		}
	}
}

// 回环来源免认证：托盘 /stats 与系统代理都拿不到凭据，配了鉴权也必须能读到指标。
func TestStatsEndpointServedWithoutAuthFromLoopback(t *testing.T) {
	s := &HTTPProxyServer{
		username: "u",
		password: "p",
		handler:  NewStreamHandler(&mockTransport{}, nil, shaper.Config{}, config.Timeouts{}),
	}
	r := httptest.NewRequest(http.MethodGet, "/stats", nil)
	r.RemoteAddr = "[::1]:4321"
	r.Host = "[::1]:4321"
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("loopback /stats without credentials = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestStatsEndpointServesLoopback(t *testing.T) {
	s := &HTTPProxyServer{
		handler: NewStreamHandler(&mockTransport{}, nil, shaper.Config{}, config.Timeouts{}),
	}
	r := httptest.NewRequest(http.MethodGet, "/stats", nil)
	r.RemoteAddr = "127.0.0.1:4321"
	r.Host = "127.0.0.1:4321"
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("loopback /stats = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

// TestControlEndpointsRejectForeignHost 固定 DNS rebinding 防线：rebinding 请求在
// TCP 层确实来自回环（RemoteAddr 无法区分），但 Host 仍是攻击者的域名，所以控制端点
// 只接受回环 IP 字面量 Host，端口还必须与监听端口一致。
func TestControlEndpointsRejectForeignHost(t *testing.T) {
	t.Parallel()

	s := &HTTPProxyServer{listenAddr: "127.0.0.1:5080"}
	for _, tc := range []struct{ path, host string }{
		{"/stats", "evil.example:5080"},
		{"/stats", "evil.example"},
		{"/stats", "localhost:5080"},
		{"/stats", "127.0.0.1:9999"},
		{"/tun", "evil.example:5080"},
	} {
		t.Run(tc.path+"@"+tc.host, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			r.RemoteAddr = "127.0.0.1:4321"
			r.Host = tc.host
			w := httptest.NewRecorder()

			s.ServeHTTP(w, r)

			if w.Code != http.StatusForbidden {
				t.Fatalf("%s with Host %q = %d, want %d", tc.path, tc.host, w.Code, http.StatusForbidden)
			}
		})
	}
}

// TestControlEndpointsAcceptLoopbackHost 正向固定托盘与 TUN helper 的调用形态：Host 是
// 回环字面量、端口与监听端口一致（bind_all 时监听 [::]，本机消费方用 [::1]）。
func TestControlEndpointsAcceptLoopbackHost(t *testing.T) {
	t.Parallel()

	s := &HTTPProxyServer{
		listenAddr: "[::]:5080",
		handler:    NewStreamHandler(&mockTransport{}, nil, shaper.Config{}, config.Timeouts{}),
	}
	for _, tc := range []struct {
		path, host string
		want       int
	}{
		{"/stats", "127.0.0.1:5080", http.StatusOK},
		{"/stats", "[::1]:5080", http.StatusOK},
		{"/tun", "[::1]:5080", http.StatusServiceUnavailable}, // 未注册 TUN 配置
	} {
		t.Run(tc.path+"@"+tc.host, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			r.RemoteAddr = "[::1]:4321"
			r.Host = tc.host
			w := httptest.NewRecorder()

			s.ServeHTTP(w, r)

			if w.Code != tc.want {
				t.Fatalf("%s with Host %q = %d, want %d", tc.path, tc.host, w.Code, tc.want)
			}
		})
	}
}
