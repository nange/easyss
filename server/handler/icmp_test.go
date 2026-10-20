package handler

import (
	"testing"

	"github.com/nange/easyss/v3/util"
)

func TestLanHostOf(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"8.8.8.8", "8.8.8.8"},              // 裸 IP（IPConn.RemoteAddr）
		{"8.8.8.8:9", "8.8.8.8"},            // TCP/UDP 形式
		{"2001:db8::1", "2001:db8::1"},      // 裸 IPv6
		{"[2001:db8::1]:53", "2001:db8::1"}, // 带端口的 IPv6
		{"fe80::1%en0", "fe80::1"},          // 带 zone 的裸 IPv6
		{"[fe80::1%en0]:0", "fe80::1%en0"},  // 带端口和 zone 的 IPv6
		{"", ""},
	}
	for _, tt := range tests {
		if got := lanHostOf(tt.in); got != tt.want {
			t.Errorf("lanHostOf(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestLanHostOfSSRFGuard 固定拨号后的 SSRF 检查：从 IPConn 风格的裸地址提取出的主机
// 必须原样传给 util.IsLANIP，否则解析到 LAN 主机的 DNS 重绑定名称就会绕过防护。
func TestLanHostOfSSRFGuard(t *testing.T) {
	for _, lan := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "fe80::1"} {
		if !util.IsLANIP(lanHostOf(lan)) {
			t.Errorf("lan host %q must be rejected by the SSRF guard", lan)
		}
	}
	for _, pub := range []string{"8.8.8.8", "1.1.1.1:53", "2001:4860:4860::8888"} {
		if util.IsLANIP(lanHostOf(pub)) {
			t.Errorf("public host %q must pass the SSRF guard", pub)
		}
	}
}

// TestICMPFirstReadBufSize 守住常规 ping 只借小缓冲：回显应答的数据部分由请求决定，
// 按请求推导后只有大请求才触及 64KB 档。断言纯函数是因为真实 ICMP 需要 root 与可达目标。
func TestICMPFirstReadBufSize(t *testing.T) {
	tests := []struct {
		name    string
		payload int
		want    int
	}{
		// 常规 ping：8 字节 ICMP 头 + 56 字节数据 → 远小于最小档位，取最小档位。
		{"shell ping", 8 + 56, icmpMinReadBufSize},
		{"empty request", 4, icmpMinReadBufSize},
		// 恰好落在最小档位边界。
		{"exactly min", icmpMinReadBufSize - icmpIPHeaderReserve + 4, icmpMinReadBufSize},
		// 超过最小档位后按请求增长（数据部分 + IP 头预留）。
		{"grows with request", 8192 + 4, 8192 + icmpIPHeaderReserve},
		// 超过上限时钳制到单个 IP 报文的最大长度。
		{"clamped to ip max", 70000, icmpMaxReadBufSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := icmpFirstReadBufSize(make([]byte, tt.payload))
			if got != tt.want {
				t.Fatalf("icmpFirstReadBufSize(%d) = %d, want %d", tt.payload, got, tt.want)
			}
			if got < icmpMinReadBufSize || got > icmpMaxReadBufSize {
				t.Fatalf("size %d 超出 [%d, %d]", got, icmpMinReadBufSize, icmpMaxReadBufSize)
			}
		})
	}
}
