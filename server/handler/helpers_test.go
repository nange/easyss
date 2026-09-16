package handler

import (
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
)

func TestIsIPv6Target(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"IPv6 地址", "2001:db8::1", true},
		{"IPv6 地址带端口", "[2001:db8::1]:8080", true},
		{"IPv6 环回", "::1", true},
		{"IPv6 环回带端口", "[::1]:80", true},
		{"IPv4 地址", "192.168.1.1", false},
		{"IPv4 地址带端口", "192.168.1.1:8080", false},
		{"域名", "example.com", false},
		{"域名带端口", "example.com:443", false},
		{"空字符串", "", false},
		{"无效地址", "not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isIPv6Target(tt.target)
			if got != tt.want {
				t.Errorf("isIPv6Target(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestNewProxyHandler(t *testing.T) {
	t.Run("空 allowedMethods 使用默认", func(t *testing.T) {
		cfg := ProxyHandlerConfig{
			MasterKey:      []byte("test-key-32-bytes-long!!!!!!!"),
			AllowedMethods: nil,
			Timeouts:       sharedconfig.NewTimeouts(5 * time.Second),
		}
		h := NewProxyHandler(cfg)
		if h == nil {
			t.Fatal("NewProxyHandler returned nil")
		}
		if len(h.allowedMethods) != 2 {
			t.Errorf("expected 2 default methods, got %d", len(h.allowedMethods))
		}
		if !h.allowedMethods[protocol.MethodAES256GCM] {
			t.Error("AES256GCM should be allowed by default")
		}
		if !h.allowedMethods[protocol.MethodChaCha20Poly1305] {
			t.Error("ChaCha20Poly1305 should be allowed by default")
		}
	})

	t.Run("指定 allowedMethods", func(t *testing.T) {
		cfg := ProxyHandlerConfig{
			MasterKey:      []byte("test-key-32-bytes-long!!!!!!!"),
			AllowedMethods: []string{"aes-256-gcm"},
			Timeouts:       sharedconfig.NewTimeouts(5 * time.Second),
		}
		h := NewProxyHandler(cfg)
		if len(h.allowedMethods) != 1 {
			t.Errorf("expected 1 method, got %d", len(h.allowedMethods))
		}
		if !h.allowedMethods[protocol.MethodAES256GCM] {
			t.Error("AES256GCM should be allowed")
		}
		if h.allowedMethods[protocol.MethodChaCha20Poly1305] {
			t.Error("ChaCha20Poly1305 should not be allowed")
		}
	})

	t.Run("无效 method 名称被忽略", func(t *testing.T) {
		cfg := ProxyHandlerConfig{
			MasterKey:      []byte("test-key-32-bytes-long!!!!!!!"),
			AllowedMethods: []string{"invalid-method", "aes-256-gcm"},
			Timeouts:       sharedconfig.NewTimeouts(5 * time.Second),
		}
		h := NewProxyHandler(cfg)
		if len(h.allowedMethods) != 1 {
			t.Errorf("expected 1 valid method, got %d", len(h.allowedMethods))
		}
	})

	t.Run("BatchWindowMS 默认值", func(t *testing.T) {
		cfg := ProxyHandlerConfig{
			MasterKey: []byte("test-key-32-bytes-long!!!!!!!"),
			Timeouts:  sharedconfig.NewTimeouts(5 * time.Second),
		}
		h := NewProxyHandler(cfg)
		if h.shaperCfg.BatchWindowMS != sharedconfig.DefaultBatchWindowMS {
			t.Errorf("BatchWindowMS = %d, want %d", h.shaperCfg.BatchWindowMS, sharedconfig.DefaultBatchWindowMS)
		}
		if h.shaperCfg.Cover.BudgetRatio != sharedconfig.DefaultCoverBudgetRatio {
			t.Errorf("CoverBudgetRatio = %v, want %v", h.shaperCfg.Cover.BudgetRatio, sharedconfig.DefaultCoverBudgetRatio)
		}
		if h.shaperCfg.Cover.BudgetCap != sharedconfig.DefaultCoverBudgetCap {
			t.Errorf("CoverBudgetCap = %d, want %d", h.shaperCfg.Cover.BudgetCap, sharedconfig.DefaultCoverBudgetCap)
		}
	})

	t.Run("BatchWindowMS 上限 10", func(t *testing.T) {
		cfg := ProxyHandlerConfig{
			MasterKey: []byte("test-key-32-bytes-long!!!!!!!"),
			Shaper:    shaper.Config{BatchWindowMS: 100},
			Timeouts:  sharedconfig.NewTimeouts(5 * time.Second),
		}
		h := NewProxyHandler(cfg)
		if h.shaperCfg.BatchWindowMS != 10 {
			t.Errorf("BatchWindowMS = %d, want 10 (capped)", h.shaperCfg.BatchWindowMS)
		}
	})

	t.Run("子 handler 非 nil", func(t *testing.T) {
		cfg := ProxyHandlerConfig{
			MasterKey: []byte("test-key-32-bytes-long!!!!!!!"),
			Timeouts:  sharedconfig.NewTimeouts(5 * time.Second),
		}
		h := NewProxyHandler(cfg)
		if h.tcp == nil {
			t.Error("tcp handler should not be nil")
		}
		if h.udp == nil {
			t.Error("udp handler should not be nil")
		}
		if h.icmp == nil {
			t.Error("icmp handler should not be nil")
		}
	})
}

func TestNewTCPHandler_DialTimeout(t *testing.T) {
	h := newTCPHandler(120*time.Second, 30*time.Second, nil)
	if h == nil {
		t.Fatal("newTCPHandler returned nil")
	}
	if h.dialTimeout != 10*time.Second {
		t.Errorf("dialTimeout = %v, want 10s", h.dialTimeout)
	}
}

func TestNewTCPHandler(t *testing.T) {
	h := newTCPHandler(120*time.Second, 30*time.Second, nil)
	if h == nil {
		t.Fatal("newTCPHandler returned nil")
	}
}

func TestNewUDPHandler(t *testing.T) {
	h := newUDPHandler(30*time.Second, 30*time.Second, nil)
	if h == nil {
		t.Fatal("newUDPHandler returned nil")
	}
	if h.dialTimeout != 10*time.Second {
		t.Errorf("dialTimeout = %v, want 10s (DialTimeout(30s))", h.dialTimeout)
	}
}

func TestNewICMPHandler(t *testing.T) {
	h := newICMPHandler(30 * time.Second)
	if h == nil {
		t.Fatal("newICMPHandler returned nil")
	}
	if h.dialTimeout != 10*time.Second {
		t.Errorf("dialTimeout = %v, want 10s (DialTimeout(30s))", h.dialTimeout)
	}
}
