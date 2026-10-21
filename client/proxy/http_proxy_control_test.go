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
