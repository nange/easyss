package runner

import (
	"net"
	"testing"
)

// TestLocalProxyAddrs 钉住本地代理入口的"监听地址 + 拨号地址"配对：
// bind_all 时监听 [::]，拨号必须换成同族回环 [::1]，而不是写死的 127.0.0.1。
func TestLocalProxyAddrs(t *testing.T) {
	tests := []struct {
		name       string
		bindAll    bool
		port       int
		wantListen string
		wantDial   string
	}{
		{
			name:       "loopback only",
			bindAll:    false,
			port:       4080,
			wantListen: "127.0.0.1:4080",
			wantDial:   "127.0.0.1:4080",
		},
		{
			name:       "bind all",
			bindAll:    true,
			port:       4080,
			wantListen: "[::]:4080",
			wantDial:   "[::1]:4080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listen, dial := localProxyAddrs(tt.bindAll, tt.port)
			if listen != tt.wantListen {
				t.Errorf("listen = %q, want %q", listen, tt.wantListen)
			}
			if dial != tt.wantDial {
				t.Errorf("dial = %q, want %q", dial, tt.wantDial)
			}
		})
	}
}

// TestLocalProxyDialAddrReachesIPv6OnlyListener 模拟 bindv6only=1 的平台：
// 本地 SOCKS5 入口只监听 IPv6（tcp6 强制 IPV6_V6ONLY=1），HTTP 入口拿到的
// 拨号地址仍必须连得上。旧实现固定拼 127.0.0.1:port，在这里会连接失败，
// 表现为 bind_all 下 HTTP 代理的反向代理与回退路径全部不可用。
func TestLocalProxyDialAddrReachesIPv6OnlyListener(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::]:0")
	if err != nil {
		t.Skipf("ipv6 loopback unavailable: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	port := ln.Addr().(*net.TCPAddr).Port
	_, dial := localProxyAddrs(true, port)
	conn, err := net.Dial("tcp", dial)
	if err != nil {
		t.Fatalf("the address handed to the HTTP proxy (%s) cannot reach an IPv6-only "+
			"SOCKS5 listener: %v", dial, err)
	}
	_ = conn.Close()
}
