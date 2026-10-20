package util

import (
	"net"
	"testing"
)

// TestLocalProxyListenAddr 钉住本地代理入口的监听地址：bind_all 时监听 [::]，
// 否则只监听 IPv4 回环。
func TestLocalProxyListenAddr(t *testing.T) {
	tests := []struct {
		name    string
		bindAll bool
		port    int
		want    string
	}{
		{
			name: "loopback only",
			port: 4080,
			want: "127.0.0.1:4080",
		},
		{
			name:    "bind all",
			bindAll: true,
			port:    4080,
			want:    "[::]:4080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LocalProxyListenAddr(tt.bindAll, tt.port); got != tt.want {
				t.Errorf("LocalProxyListenAddr(%v, %d) = %q, want %q",
					tt.bindAll, tt.port, got, tt.want)
			}
		})
	}
}

// TestLocalProxyDialAddr 钉住"拨号地址由监听地址推导"：监听通配地址时换成同族
// 回环，只监听 IPv4 回环时保持原样。
func TestLocalProxyDialAddr(t *testing.T) {
	tests := []struct {
		name    string
		bindAll bool
		port    int
		want    string
	}{
		{
			name: "ipv4 loopback",
			port: 4080,
			want: "127.0.0.1:4080",
		},
		{
			name:    "ipv6 wildcard",
			bindAll: true,
			port:    4080,
			want:    "[::1]:4080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LocalProxyDialAddr(tt.bindAll, tt.port); got != tt.want {
				t.Errorf("LocalProxyDialAddr(%v, %d) = %q, want %q",
					tt.bindAll, tt.port, got, tt.want)
			}
		})
	}
}

// TestLocalProxyDialAddrReachesIPv6OnlyListener 模拟监听实际只接受 IPv6 的
// 平台：tcp6 强制 IPV6_V6ONLY=1，本地消费方拿到的拨号地址仍必须连得上。
// 固定拼 127.0.0.1:port 的实现在这里会连接失败，表现为 bind_all 下 HTTP
// 入口的反向代理、TUN 引擎与系统代理全部不可用。
func TestLocalProxyDialAddrReachesIPv6OnlyListener(t *testing.T) {
	ln, err := net.Listen("tcp6", LocalProxyListenAddr(true, 0))
	if err != nil {
		t.Skipf("ipv6 loopback unavailable: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	port := ln.Addr().(*net.TCPAddr).Port
	dial := LocalProxyDialAddr(true, port)
	conn, err := net.Dial("tcp", dial)
	if err != nil {
		t.Fatalf("the dial address handed to local consumers (%s) cannot reach an "+
			"IPv6-only listener: %v", dial, err)
	}
	_ = conn.Close()
}

// TestSocks5URI 钉住 TUN 引擎拿到的 SOCKS5 端点：它必须与 bind_all 同源，
// 否则监听 [::] 的入口在只接受 IPv6 回环的环境里连不上。
func TestSocks5URI(t *testing.T) {
	tests := []struct {
		name    string
		bindAll bool
		port    int
		want    string
	}{
		{
			name: "loopback only",
			port: 4080,
			want: "socks5://127.0.0.1:4080",
		},
		{
			name:    "bind all",
			bindAll: true,
			port:    4080,
			want:    "socks5://[::1]:4080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Socks5URI(tt.bindAll, tt.port); got != tt.want {
				t.Errorf("Socks5URI(%v, %d) = %q, want %q",
					tt.bindAll, tt.port, got, tt.want)
			}
		})
	}
}
