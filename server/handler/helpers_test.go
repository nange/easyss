package handler

import (
	"context"
	"net"
	"net/netip"
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

// TestClientPreferredFamily 固定"客户端到服务端的地址族"推导：只有能确定
// 客户端用哪个族接入时才会有偏好，IPv4-mapped 形式折叠为 IPv4
// （v4 客户端经双栈监听接入时 Go 报告的就是这种形式）。
func TestClientPreferredFamily(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"ipv4", "1.2.3.4:5678", "1.2.3.4"},
		{"ipv6", "[2606:50c0:8002::154]:443", "2606:50c0:8002::154"},
		{"ipv4-mapped folds to ipv4", "[::ffff:1.2.3.4]:443", "1.2.3.4"},
		{"loopback ipv4", "127.0.0.1:1234", "127.0.0.1"},
		{"no port", "1.2.3.4", ""},
		{"garbage", "not-an-address", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientPreferredFamily(tt.remoteAddr)
			if tt.want == "" {
				if got.IsValid() {
					t.Fatalf("clientPreferredFamily(%q) = %v, want the zero value", tt.remoteAddr, got)
				}
				return
			}
			if got.String() != tt.want {
				t.Fatalf("clientPreferredFamily(%q) = %v, want %v", tt.remoteAddr, got, tt.want)
			}
		})
	}
}

// TestPreferredFamilyContext 覆盖族提示在 context 中的往返：零值不写入，
// 没有提示的 context 读出无偏好，使拨号退化为系统默认排序。
func TestPreferredFamilyContext(t *testing.T) {
	if _, ok := preferredFamily(t.Context()); ok {
		t.Fatal("a bare context should report no preference")
	}
	if preferredOrNone(t.Context()).IsValid() {
		t.Fatal("preferredOrNone on a bare context should be the zero value")
	}

	want := netip.MustParseAddr("93.184.216.34")
	ctx := withPreferredFamily(t.Context(), want)
	got, ok := preferredFamily(ctx)
	if !ok || got != want {
		t.Fatalf("preferredFamily = (%v, %v), want (%v, true)", got, ok, want)
	}

	if got := withPreferredFamily(t.Context(), netip.Addr{}); got.Value(ctxPreferredFamily) != nil {
		t.Fatal("an invalid address must not be stored as a preference")
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

// TestTCPDialerOptions 固定了基础超时到直连拨号器参数的映射：Timeout 经由
// config.DialTimeout（base/3，限制在 [3s, 15s]）派生，而 KeepAlive 保留完整的基础超时，
// 使长连接流由内核回收而不是半开地悬留。拨号器本身现在是在拨号闭包内惰性构建的，
// 因此该映射只有在这里仍然可观测。
func TestTCPDialerOptions(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		wantDialTimeout time.Duration
	}{
		{"默认值 30s", 30 * time.Second, 10 * time.Second},
		{"最小值保底", 5 * time.Second, 3 * time.Second},
		{"最大值封顶", 120 * time.Second, 15 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialTimeout, keepAlive := tcpDialerOptions(tt.timeout)
			if dialTimeout != tt.wantDialTimeout {
				t.Errorf("dialTimeout = %v, want %v", dialTimeout, tt.wantDialTimeout)
			}
			if keepAlive != tt.timeout {
				t.Errorf("keepAlive = %v, want the base timeout %v", keepAlive, tt.timeout)
			}
		})
	}
}

func TestNewTCPHandler(t *testing.T) {
	h := newTCPHandler(120*time.Second, 30*time.Second, nil)
	if h == nil {
		t.Fatal("newTCPHandler returned nil")
	}
	if h.idleTimeout != 120*time.Second {
		t.Errorf("idleTimeout = %v, want 120s", h.idleTimeout)
	}
}

// TestTCPHandlerDialTarget 覆盖 TCP handler 共享的拨号部分：直连拨号根据目标字面量
// 解析网络，拨号后的 SSRF 防护会拒绝 LAN 远端地址。拨号超时和 keepalive 都无法从
// 已建立的连接上观测到，因此基础超时的映射由 TestTCPDialerOptions 覆盖。
func TestTCPHandlerDialTarget(t *testing.T) {
	t.Run("按目标字面量选择网络", func(t *testing.T) {
		h := newTCPHandler(120*time.Second, 30*time.Second, nil)
		var gotNetwork, gotTarget string
		h.dialContext = func(_ context.Context, network, target string) (net.Conn, error) {
			gotNetwork, gotTarget = network, target
			return newStubConn(&net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}), nil
		}

		if _, _, err := h.dial.dialTarget(t.Context(), "tcp", "8.8.8.8:53"); err != nil {
			t.Fatalf("dialTarget: %v", err)
		}
		if gotNetwork != "tcp" || gotTarget != "8.8.8.8:53" {
			t.Errorf("dialed %q %q, want \"tcp\" \"8.8.8.8:53\"", gotNetwork, gotTarget)
		}
	})

	t.Run("拨号后拒绝 LAN 目标", func(t *testing.T) {
		h := newTCPHandler(120*time.Second, 30*time.Second, nil)
		stub := newStubConn(&net.TCPAddr{IP: net.ParseIP("192.168.7.7"), Port: 80})
		h.dialContext = func(context.Context, string, string) (net.Conn, error) { return stub, nil }

		if _, _, err := h.dial.dialTarget(t.Context(), "tcp", "192.168.7.7:80"); err == nil {
			t.Fatal("dialTarget accepted a LAN remote address")
		}
		if !stub.isClosed() {
			t.Error("rejected connection was not closed")
		}
	})
}

func TestNewUDPHandler(t *testing.T) {
	h := newUDPHandler(30*time.Second, 30*time.Second, nil)
	if h == nil {
		t.Fatal("newUDPHandler returned nil")
	}
	if h.idleTimeout != 30*time.Second {
		t.Errorf("idleTimeout = %v, want 30s", h.idleTimeout)
	}
	if h.nextProxy != nil {
		t.Error("nextProxy should stay nil when none is configured")
	}
}

// TestNewICMPHandler 只检查构造：所有 ICMP 拨号失败路径都走共享的 dialer
// （由 TestTCPHandlerDialTarget 覆盖），而真正进行 ICMP 交换需要原始套接字权限。
// 拨号超时通过 config.DialTimeout 派生，由 config.TestDialTimeout 固定。
func TestNewICMPHandler(t *testing.T) {
	h := newICMPHandler(30 * time.Second)
	if h == nil {
		t.Fatal("newICMPHandler returned nil")
	}
	if h.dial.nextProxy != nil || h.dial.shouldProxy != nil {
		t.Error("ICMP must not route through a next proxy")
	}
}
