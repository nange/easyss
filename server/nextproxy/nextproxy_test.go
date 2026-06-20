package nextproxy

import (
	"net"
	"testing"
)

func TestNew(t *testing.T) {
	t.Run("正常 URL", func(t *testing.T) {
		np, err := New("http://proxy.example.com:8080", true, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if np == nil {
			t.Fatal("expected non-nil NextProxy")
		}
		if u := np.URL(); u == nil || u.Host != "proxy.example.com:8080" {
			t.Errorf("URL host = %v", u)
		}
		if !np.EnableUDP() {
			t.Error("EnableUDP should be true")
		}
	})

	t.Run("空 URL 返回 nil", func(t *testing.T) {
		np, err := New("", false, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if np != nil {
			t.Error("expected nil for empty URL")
		}
	})

	t.Run("无效 URL 返回错误", func(t *testing.T) {
		_, err := New("://invalid", false, false)
		if err == nil {
			t.Error("expected error for invalid URL")
		}
	})

	t.Run("SOCKS5 URL", func(t *testing.T) {
		np, err := New("socks5://user:pass@proxy.example.com:1080", true, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if np.url.Scheme != "socks5" {
			t.Errorf("scheme = %q", np.url.Scheme)
		}
		if np.url.Host != "proxy.example.com:1080" {
			t.Errorf("host = %q", np.url.Host)
		}
	})
}

func TestShouldProxy(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var np *NextProxy
		if np.ShouldProxy("example.com") {
			t.Error("nil receiver should return false")
		}
	})

	t.Run("allHost=true", func(t *testing.T) {
		np := &NextProxy{allHost: true}
		if !np.ShouldProxy("any-host.com") {
			t.Error("allHost should proxy everything")
		}
	})

	t.Run("IP 精确匹配", func(t *testing.T) {
		np := &NextProxy{ips: map[string]struct{}{"10.0.0.1": {}}}
		if !np.ShouldProxy("10.0.0.1") {
			t.Error("should proxy matching IP")
		}
		if np.ShouldProxy("10.0.0.2") {
			t.Error("should not proxy non-matching IP")
		}
	})

	t.Run("CIDR 匹配", func(t *testing.T) {
		np, err := New("http://proxy:8080", false, false)
		if err != nil {
			t.Fatal(err)
		}
		// 手动填充 CIDR 列表
		np.ips = map[string]struct{}{}
		_ = np.LoadProxyFile("") // 空文件初始化 maps
		np.cidrIPs = append(np.cidrIPs, mustParseCIDR(t, "192.168.0.0/16"))

		if !np.ShouldProxy("192.168.1.1") {
			t.Error("should proxy CIDR-matching IP")
		}
		if np.ShouldProxy("10.0.0.1") {
			t.Error("should not proxy non-CIDR-matching IP")
		}
	})

	t.Run("域名匹配", func(t *testing.T) {
		np := &NextProxy{domains: map[string]struct{}{"example.com": {}}}
		if !np.ShouldProxy("example.com") {
			t.Error("should proxy matching domain")
		}
		if np.ShouldProxy("other.com") {
			t.Error("should not proxy non-matching domain")
		}
	})

	t.Run("带端口的 host", func(t *testing.T) {
		np := &NextProxy{
			ips:     map[string]struct{}{"10.0.0.1": {}},
			domains: map[string]struct{}{"example.com": {}},
		}
		if !np.ShouldProxy("10.0.0.1:8080") {
			t.Error("should proxy IP:port")
		}
		if !np.ShouldProxy("example.com:443") {
			t.Error("should proxy domain:port")
		}
	})
}

func TestURL(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var np *NextProxy
		if u := np.URL(); u != nil {
			t.Errorf("expected nil, got %v", u)
		}
	})

	t.Run("正常返回", func(t *testing.T) {
		np, err := New("http://proxy.example.com:8080", false, false)
		if err != nil {
			t.Fatal(err)
		}
		u := np.URL()
		if u == nil || u.Host != "proxy.example.com:8080" {
			t.Errorf("URL = %v", u)
		}
	})
}

func TestEnableUDP(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var np *NextProxy
		if np.EnableUDP() {
			t.Error("nil receiver should return false")
		}
	})

	t.Run("正常返回", func(t *testing.T) {
		np, err := New("http://proxy:8080", true, false)
		if err != nil {
			t.Fatal(err)
		}
		if !np.EnableUDP() {
			t.Error("EnableUDP should be true")
		}
	})
}

func mustParseCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return ipnet
}
