package util

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIP(t *testing.T) {
	assert.True(t, IsIP("127.0.0.1"))
	assert.False(t, IsIP("127.0.0"))

	assert.True(t, IsLANIP("192.168.0.1"))
	assert.False(t, IsLANIP(" "))

	assert.False(t, IsLANIP("183.47.103.43"))

	assert.True(t, IsLoopbackIP("127.0.0.1"))
	assert.True(t, IsLoopbackIP("::1"))

	assert.True(t, IsIPV6("::0"))
	assert.False(t, IsIPV6("127.0.1"))
}

func TestIsIP_EdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// IPv4 正常情况
		{"0.0.0.0", true},
		{"255.255.255.255", true},
		{"1.2.3.4", true},
		// IPv6 各种表示法
		{"::1", true},
		{"::", true},
		{"2001:db8::1", true},
		{"2001:db8:0:0:0:0:2:1", true},
		{"2001:db8::2:1", true},
		{"::ffff:192.0.2.1", true}, // IPv4-mapped IPv6
		// 无效输入
		{"", false},
		{"not-an-ip", false},
		{"256.256.256.256", false},
		{"192.168.1", false},
		{"192.168.1.1.1", false},
		{"example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsIP(tt.input)
			if got != tt.want {
				t.Errorf("IsIP(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsLANIP_EdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// 私有地址段
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		// 环回
		{"127.0.0.1", true},
		{"127.255.255.255", true},
		{"::1", true},
		// 链路本地
		{"169.254.0.1", true},
		{"fe80::1", true},
		// 未指定
		{"0.0.0.0", true},
		{"::", true},
		// 多播
		{"224.0.0.1", true},
		{"ff02::1", true},
		// 公网地址
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"183.47.103.43", false},
		// 无效输入
		{"", false},
		{"not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsLANIP(tt.input)
			if got != tt.want {
				t.Errorf("IsLANIP(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsLoopbackIP_EdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.0", true},
		{"127.255.255.255", true},
		{"::1", true},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
		{"", false},
		{"not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsLoopbackIP(tt.input)
			if got != tt.want {
				t.Errorf("IsLoopbackIP(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsIPV6_EdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"::1", true},
		{"::", true},
		{"2001:db8::1", true},
		{"fe80::1", true},
		{"ff02::1", true},
		// IPv4-mapped IPv6 地址的 To4() 能提取 IPv4，所以 IsIPV6 返回 false
		{"::ffff:192.0.2.1", false},
		{"192.168.1.1", false},
		{"127.0.0.1", false},
		{"", false},
		{"not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsIPV6(tt.input)
			if got != tt.want {
				t.Errorf("IsIPV6(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsIPV6Addr(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"[::1]:8080", true},
		{"[2001:db8::1]:443", true},
		{"192.168.1.1:8080", false},
		{"example.com:443", false},
		{"", false},
		// SplitHostPort 无法解析纯 IPv6 不带方括号的情况
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsIPV6Addr(tt.input)
			if got != tt.want {
				t.Errorf("IsIPV6Addr(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsLANHost(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// IPv4 私有地址 + 端口
		{"10.0.0.1:8080", true},
		{"172.16.0.1:443", true},
		{"192.168.1.1:80", true},
		// IPv4 回环 + 端口
		{"127.0.0.1:6379", true},
		{"127.0.0.1:0", true},
		// IPv6 私有地址 + 端口
		{"[fd00::1]:8080", true},
		// IPv6 回环 + 端口
		{"[::1]:8080", true},
		// 链路本地 + 端口
		{"169.254.0.1:80", true},
		{"[fe80::1]:443", true},
		// 公网 IP + 端口
		{"8.8.8.8:53", false},
		{"1.1.1.1:443", false},
		{"[2001:db8::1]:8080", false},
		// 纯 IP 不带端口（如 ICMP target）
		{"127.0.0.1", true},
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"8.8.8.8", false},
		// 域名（非 IP）
		{"example.com:443", false},
		{"api.example.com:8080", false},
		// 无效输入
		{"", false},
		{":8080", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsLANHost(tt.input)
			if got != tt.want {
				t.Errorf("IsLANHost(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsLANHostResolved(t *testing.T) {
	ctx := context.Background()

	// Literal LAN IPs are caught by the fast path (no DNS).
	assert.True(t, IsLANHostResolved(ctx, "127.0.0.1:8080"))
	assert.True(t, IsLANHostResolved(ctx, "10.0.0.1"))
	assert.True(t, IsLANHostResolved(ctx, "[::1]:80"))

	// Literal public IPs are rejected by the fast path.
	assert.False(t, IsLANHostResolved(ctx, "8.8.8.8:53"))
	assert.False(t, IsLANHostResolved(ctx, "1.1.1.1"))

	// "localhost" resolves (via the hosts file, no external network) to a
	// loopback address, so a domain that points at the LAN is now rejected.
	assert.True(t, IsLANHostResolved(ctx, "localhost:80"))
	assert.True(t, IsLANHostResolved(ctx, "localhost"))

	// Empty / invalid input never resolves to LAN.
	assert.False(t, IsLANHostResolved(ctx, ""))
	assert.False(t, IsLANHostResolved(ctx, "invalid:0"))
}

func TestMapKeys(t *testing.T) {
	t.Run("string keys", func(t *testing.T) {
		m := map[string]int{"a": 1, "b": 2, "c": 3}
		keys := MapKeys(m)
		if len(keys) != 3 {
			t.Errorf("len = %d, want 3", len(keys))
		}
		// 验证所有 key 都在结果中
		seen := make(map[string]bool)
		for _, k := range keys {
			seen[k] = true
		}
		for k := range m {
			if !seen[k] {
				t.Errorf("key %q missing from result", k)
			}
		}
	})

	t.Run("empty map", func(t *testing.T) {
		m := map[string]int{}
		keys := MapKeys(m)
		if len(keys) != 0 {
			t.Errorf("len = %d, want 0", len(keys))
		}
	})

	t.Run("int keys", func(t *testing.T) {
		m := map[int]string{1: "one", 2: "two"}
		keys := MapKeys(m)
		if len(keys) != 2 {
			t.Errorf("len = %d, want 2", len(keys))
		}
	})
}
