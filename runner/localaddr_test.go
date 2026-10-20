package runner

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
			if got := localProxyListenAddr(tt.bindAll, tt.port); got != tt.want {
				t.Errorf("localProxyListenAddr(%v, %d) = %q, want %q",
					tt.bindAll, tt.port, got, tt.want)
			}
		})
	}
}

// TestLocalProxyDialAddr 钉住"拨号地址由监听地址推导"：通配地址换成同族回环，
// 非通配地址保持原样。
func TestLocalProxyDialAddr(t *testing.T) {
	tests := []struct {
		name   string
		listen string
		want   string
	}{
		{
			name:   "ipv4 loopback",
			listen: "127.0.0.1:4080",
			want:   "127.0.0.1:4080",
		},
		{
			name:   "ipv6 wildcard",
			listen: "[::]:4080",
			want:   "[::1]:4080",
		},
		{
			name:   "ipv6 loopback",
			listen: "[::1]:4080",
			want:   "[::1]:4080",
		},
		{
			name:   "ipv4 wildcard",
			listen: "0.0.0.0:4080",
			want:   "127.0.0.1:4080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := localProxyDialAddr(tt.listen); got != tt.want {
				t.Errorf("localProxyDialAddr(%q) = %q, want %q", tt.listen, got, tt.want)
			}
		})
	}
}

// TestLocalProxyDialAddrReachesIPv6OnlyListener 模拟监听实际只接受 IPv6 的
// 平台：tcp6 强制 IPV6_V6ONLY=1，HTTP 入口拿到的拨号地址仍必须连得上。
// 旧实现固定拼 127.0.0.1:port，在这里会连接失败，表现为 bind_all 下 HTTP
// 代理的反向代理与回退路径全部不可用。
func TestLocalProxyDialAddrReachesIPv6OnlyListener(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::]:0")
	if err != nil {
		t.Skipf("ipv6 loopback unavailable: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	port := ln.Addr().(*net.TCPAddr).Port
	dial := localProxyDialAddr(localProxyListenAddr(true, port))
	conn, err := net.Dial("tcp", dial)
	if err != nil {
		t.Fatalf("the address handed to the HTTP proxy (%s) cannot reach an IPv6-only "+
			"SOCKS5 listener: %v", dial, err)
	}
	_ = conn.Close()
}
