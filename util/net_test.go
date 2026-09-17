package util

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{"::ffff:192.0.2.1", true}, // IPv4 映射的 IPv6
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
		// CGNAT / 保留 / 测试网段 / 广播（SSRF 防护必须拦截）
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"0.1.2.3", true},
		{"192.0.0.9", true},
		{"192.0.2.1", true},
		{"198.18.0.1", true},
		{"198.19.255.255", true},
		{"198.51.100.7", true},
		{"203.0.113.9", true},
		{"240.0.0.1", true},
		{"255.255.255.255", true},
		{"::ffff:127.0.0.1", true},
		{"::ffff:100.64.0.1", true},
		// 公网地址
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"183.47.103.43", false},
		{"100.63.255.255", false},
		{"100.128.0.1", false},
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

// TestResolveHostIPs 固定解析契约：字面 IP 不查 DNS 且保留 zone，域名返回全部
// 地址并折叠 IPv4-mapped，解析失败返回错误（而不是旧的「失败即放行」）。
func TestResolveHostIPs(t *testing.T) {
	ctx := context.Background()

	t.Run("字面 IP 不发起解析", func(t *testing.T) {
		for _, tt := range []struct{ addr, want string }{
			{"127.0.0.1:8080", "127.0.0.1"},
			{"10.0.0.1", "10.0.0.1"},
			{"[::1]:80", "::1"},
			{"8.8.8.8:53", "8.8.8.8"},
			{"[fe80::1%eth0]:443", "fe80::1%eth0"},
		} {
			addrs, err := ResolveHostIPs(ctx, tt.addr)
			require.NoError(t, err)
			require.Len(t, addrs, 1, "literal %s should yield exactly one address", tt.addr)
			assert.Equal(t, tt.want, addrs[0].String())
		}
	})

	t.Run("域名解析到 LAN", func(t *testing.T) {
		// "localhost" 通过 hosts 文件解析，不依赖外部网络。
		addrs, err := ResolveHostIPs(ctx, "localhost:80")
		require.NoError(t, err)
		assert.True(t, FirstLANAddr(addrs).IsValid(), "localhost should resolve to a LAN address: %v", addrs)
	})

	t.Run("解析失败返回错误", func(t *testing.T) {
		for _, addr := range []string{"", "invalid:0", "no-such-host-for-easyss-test.invalid:80"} {
			if _, err := ResolveHostIPs(ctx, addr); err == nil {
				t.Errorf("ResolveHostIPs(%q) returned no error", addr)
			}
		}
	})

	t.Run("ctx 已取消", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := ResolveHostIPs(canceled, "example.com:443"); err == nil {
			t.Error("a canceled context should fail the resolution")
		}
	})
}

// TestFirstLANAddr 覆盖「任一路径为 LAN 即拒绝」的判定，包括带 zone 的链路本地
// 地址（net.ParseIP 无法解析带 zone 的地址，必须先剥掉否则会漏判）。
func TestFirstLANAddr(t *testing.T) {
	tests := []struct {
		name string
		ips  []string
		want string
	}{
		{name: "全部公网", ips: []string{"8.8.8.8", "2606:4700:4700::1111"}, want: ""},
		{name: "混合时命中私网", ips: []string{"8.8.8.8", "10.0.0.1"}, want: "10.0.0.1"},
		{name: "回环", ips: []string{"127.0.0.1"}, want: "127.0.0.1"},
		{name: "链路本地带 zone", ips: []string{"fe80::1%eth0"}, want: "fe80::1%eth0"},
		{name: "空列表", ips: nil, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrs := make([]netip.Addr, 0, len(tt.ips))
			for _, ip := range tt.ips {
				addrs = append(addrs, netip.MustParseAddr(ip))
			}
			got := FirstLANAddr(addrs)
			if tt.want == "" {
				assert.False(t, got.IsValid(), "FirstLANAddr(%v) = %v, want the zero value", tt.ips, got)
				return
			}
			assert.Equal(t, tt.want, got.String())
		})
	}
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
