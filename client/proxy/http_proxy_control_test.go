package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/shaper"
)

// 控制端点（/tun、/stats、/icmp/*）在 bind_all 时也不能暴露到网络上。
func TestControlEndpointsRejectNonLoopback(t *testing.T) {
	s := &HTTPProxyServer{}
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/stats"},
		{http.MethodGet, "/tun"},
		{http.MethodPost, "/icmp/classify"},
		{http.MethodPost, "/icmp/proxy"},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.RemoteAddr = "203.0.113.9:4321"
		w := httptest.NewRecorder()

		s.ServeHTTP(w, r)

		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s from a non-loopback peer = %d, want %d", tc.method, tc.path, w.Code, http.StatusForbidden)
		}
	}
}

// helper 的 ICMP 分类请求没有代理凭据，必须在认证之前放行；分类复用 routePolicy。
func TestICMPClassifyAllowsLoopbackWithoutAuth(t *testing.T) {
	s := &HTTPProxyServer{}
	r := httptest.NewRequest(http.MethodPost, "/icmp/classify", strings.NewReader(`{"dst":"8.8.8.8"}`))
	r.RemoteAddr = "127.0.0.1:4321"
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("loopback /icmp/classify = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"action":"proxy"`) {
		t.Fatalf("/icmp/classify body = %s, want proxy action", w.Body.String())
	}
}

func TestICMPControlRejectsGet(t *testing.T) {
	s := &HTTPProxyServer{}
	r := httptest.NewRequest(http.MethodGet, "/icmp/classify", nil)
	r.RemoteAddr = "127.0.0.1:4321"
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /icmp/classify = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// 回环来源仍要经过认证；这条路径不触碰快照，因此不需要构造 handler。
func TestStatsEndpointStillRequiresAuth(t *testing.T) {
	s := &HTTPProxyServer{username: "u", password: "p"}
	r := httptest.NewRequest(http.MethodGet, "/stats", nil)
	r.RemoteAddr = "[::1]:4321"
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("loopback /stats without credentials = %d, want %d", w.Code, http.StatusProxyAuthRequired)
	}
}

func TestStatsEndpointServesLoopback(t *testing.T) {
	s := &HTTPProxyServer{
		handler: NewStreamHandler(&mockTransport{}, nil, shaper.Config{}, config.Timeouts{}),
	}
	r := httptest.NewRequest(http.MethodGet, "/stats", nil)
	r.RemoteAddr = "127.0.0.1:4321"
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("loopback /stats = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}
