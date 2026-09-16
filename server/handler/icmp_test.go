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
