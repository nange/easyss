package handler

import (
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
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
			MasterKey:         []byte("test-key-32-bytes-long!!!!!!!"),
			AllowedMethods:    nil,
			HandshakeTimeout:  5 * time.Second,
			StreamIdleTimeout: 300 * time.Second,
			UDPIdleTimeout:    30 * time.Second,
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
			MasterKey:         []byte("test-key-32-bytes-long!!!!!!!"),
			AllowedMethods:    []string{"aes-256-gcm"},
			HandshakeTimeout:  5 * time.Second,
			StreamIdleTimeout: 300 * time.Second,
			UDPIdleTimeout:    30 * time.Second,
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
			MasterKey:         []byte("test-key-32-bytes-long!!!!!!!"),
			AllowedMethods:    []string{"invalid-method", "aes-256-gcm"},
			HandshakeTimeout:  5 * time.Second,
			StreamIdleTimeout: 300 * time.Second,
			UDPIdleTimeout:    30 * time.Second,
		}
		h := NewProxyHandler(cfg)
		if len(h.allowedMethods) != 1 {
			t.Errorf("expected 1 valid method, got %d", len(h.allowedMethods))
		}
	})

	t.Run("BatchWindowMS 默认值", func(t *testing.T) {
		cfg := ProxyHandlerConfig{
			MasterKey:         []byte("test-key-32-bytes-long!!!!!!!"),
			HandshakeTimeout:  5 * time.Second,
			StreamIdleTimeout: 300 * time.Second,
			UDPIdleTimeout:    30 * time.Second,
		}
		h := NewProxyHandler(cfg)
		if h.batchWindowMS != sharedconfig.DefaultBatchWindowMS {
			t.Errorf("batchWindowMS = %d, want %d", h.batchWindowMS, sharedconfig.DefaultBatchWindowMS)
		}
	})

	t.Run("BatchWindowMS 上限 10", func(t *testing.T) {
		cfg := ProxyHandlerConfig{
			MasterKey:         []byte("test-key-32-bytes-long!!!!!!!"),
			BatchWindowMS:     100,
			HandshakeTimeout:  5 * time.Second,
			StreamIdleTimeout: 300 * time.Second,
			UDPIdleTimeout:    30 * time.Second,
		}
		h := NewProxyHandler(cfg)
		if h.batchWindowMS != 10 {
			t.Errorf("batchWindowMS = %d, want 10 (capped)", h.batchWindowMS)
		}
	})

	t.Run("子 handler 非 nil", func(t *testing.T) {
		cfg := ProxyHandlerConfig{
			MasterKey:         []byte("test-key-32-bytes-long!!!!!!!"),
			HandshakeTimeout:  5 * time.Second,
			StreamIdleTimeout: 300 * time.Second,
			UDPIdleTimeout:    30 * time.Second,
		}
		h := NewProxyHandler(cfg)
		if h.tcpHandler == nil {
			t.Error("tcpHandler should not be nil")
		}
		if h.udpHandler == nil {
			t.Error("udpHandler should not be nil")
		}
		if h.icmpHandler == nil {
			t.Error("icmpHandler should not be nil")
		}
	})
}

func TestDialTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"默认值 30s", 30 * time.Second, 10 * time.Second},
		{"最小值保底：0s", 0, 3 * time.Second},
		{"最小值保底：9s", 9 * time.Second, 3 * time.Second},
		{"正常值：15s", 15 * time.Second, 5 * time.Second},
		{"正常值：45s", 45 * time.Second, 15 * time.Second},
		{"最大值封顶：60s", 60 * time.Second, 15 * time.Second},
		{"最大值封顶：120s", 120 * time.Second, 15 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DialTimeout(tt.timeout)
			if got != tt.want {
				t.Errorf("DialTimeout(%v) = %v, want %v", tt.timeout, got, tt.want)
			}
		})
	}
}

func TestNewTCPHandler_DialTimeout(t *testing.T) {
	h := NewTCPHandler(120*time.Second, 30*time.Second, nil)
	if h == nil {
		t.Fatal("NewTCPHandler returned nil")
	}
	if h.dialTimeout != 10*time.Second {
		t.Errorf("dialTimeout = %v, want 10s", h.dialTimeout)
	}
	if h.dialer.Timeout != 10*time.Second {
		t.Errorf("dialer.Timeout = %v, want 10s", h.dialer.Timeout)
	}
	if h.dialer.KeepAlive != 30*time.Second {
		t.Errorf("dialer.KeepAlive = %v, want 30s", h.dialer.KeepAlive)
	}
}

func TestNewTCPHandler(t *testing.T) {
	h := NewTCPHandler(120*time.Second, 30*time.Second, nil)
	if h == nil {
		t.Fatal("NewTCPHandler returned nil")
	}
}

func TestNewUDPHandler(t *testing.T) {
	h := NewUDPHandler(30*time.Second, nil)
	if h == nil {
		t.Fatal("NewUDPHandler returned nil")
	}
}

func TestNewICMPHandler(t *testing.T) {
	h := NewICMPHandler()
	if h == nil {
		t.Fatal("NewICMPHandler returned nil")
	}
}
