package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsSelfTarget(t *testing.T) {
	s := &HTTPProxyServer{listenAddr: "[::]:8080"}

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"精确匹配 listenAddr", "[::]:8080", true},
		{"IPv4 环回", "127.0.0.1:8080", true},
		{"localhost", "localhost:8080", true},
		{"IPv6 环回", "[::1]:8080", true},
		{"端口不同", "127.0.0.1:9090", false},
		{"域名", "example.com:8080", false},
		{"缺少端口", "127.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://"+tt.target+"/", nil)
			if got := s.isSelfTarget(r); got != tt.want {
				t.Errorf("isSelfTarget(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestIsSelfTarget_LocalInterfaceIP(t *testing.T) {
	var local string
	for ip := range localIPSet() {
		if ip != "127.0.0.1" && ip != "::1" {
			local = ip
			break
		}
	}
	if local == "" {
		t.Skip("no non-loopback local IP found")
	}

	s := &HTTPProxyServer{listenAddr: "[::]:8080"}
	r := httptest.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(local, "8080")+"/", nil)
	if !s.isSelfTarget(r) {
		t.Errorf("isSelfTarget(%s:8080) should be true (local interface IP)", local)
	}

	r = httptest.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(local, "9090")+"/", nil)
	if s.isSelfTarget(r) {
		t.Errorf("isSelfTarget(%s:9090) should be false (different port)", local)
	}
}
