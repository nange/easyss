package nextproxy

import (
	"net"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/util"
)

func TestNew(t *testing.T) {
	t.Run("正常 URL", func(t *testing.T) {
		np, err := New("socks5://proxy.example.com:1080", true, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if np == nil {
			t.Fatal("expected non-nil NextProxy")
		}
		if u := np.URL(); u == nil || u.Host != "proxy.example.com:1080" {
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

	t.Run("不支持的 scheme 返回错误", func(t *testing.T) {
		_, err := New("http://proxy.example.com:8080", false, false)
		if err == nil || !strings.Contains(err.Error(), "unsupported next proxy scheme") {
			t.Fatalf("expected unsupported scheme error, got %v", err)
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
		np, err := New("socks5://proxy:1080", false, false)
		if err != nil {
			t.Fatal(err)
		}
		np.ips = map[string]struct{}{}
		_ = np.LoadProxyFile("")
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

	t.Run("子域名匹配", func(t *testing.T) {
		np := &NextProxy{domains: map[string]struct{}{"example.com": {}}}
		if !np.ShouldProxy("www.example.com") {
			t.Error("should proxy subdomain")
		}
		if !np.ShouldProxy("api.example.com") {
			t.Error("should proxy subdomain")
		}
		if np.ShouldProxy("not-example.com") {
			t.Error("should not proxy unrelated domain")
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
		np, err := New("socks5://proxy.example.com:1080", false, false)
		if err != nil {
			t.Fatal(err)
		}
		u := np.URL()
		if u == nil || u.Host != "proxy.example.com:1080" {
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
		np, err := New("socks5://proxy:1080", true, false)
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

func TestIsCustomDomain(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var np *NextProxy
		if np.IsCustomDomain("example.com") {
			t.Error("nil receiver should return false")
		}
	})

	t.Run("精确匹配", func(t *testing.T) {
		np := &NextProxy{domains: map[string]struct{}{"example.com": {}}}
		if !np.IsCustomDomain("example.com") {
			t.Error("should match exact domain")
		}
	})

	t.Run("子域名匹配", func(t *testing.T) {
		np := &NextProxy{domains: map[string]struct{}{"example.com": {}}}
		if !np.IsCustomDomain("www.example.com") {
			t.Error("should match subdomain")
		}
		if !np.IsCustomDomain("api.example.com") {
			t.Error("should match subdomain")
		}
	})

	t.Run("不匹配", func(t *testing.T) {
		np := &NextProxy{domains: map[string]struct{}{"example.com": {}}}
		if np.IsCustomDomain("other.com") {
			t.Error("should not match unrelated domain")
		}
		if np.IsCustomDomain("not-example.com") {
			t.Error("should not match domain with different suffix")
		}
	})
}

func TestAddIP(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var np *NextProxy
		np.AddIP("1.2.3.4") // should not panic
	})

	t.Run("添加 IP", func(t *testing.T) {
		np := &NextProxy{ips: make(map[string]struct{})}
		np.AddIP("1.2.3.4")
		if !np.ShouldProxy("1.2.3.4") {
			t.Error("should proxy after AddIP")
		}
	})

	t.Run("去重", func(t *testing.T) {
		np := &NextProxy{ips: make(map[string]struct{})}
		np.AddIP("1.2.3.4")
		np.AddIP("1.2.3.4")
		count := 0
		np.mu.RLock()
		count = len(np.ips)
		np.mu.RUnlock()
		if count != 1 {
			t.Errorf("expected 1 IP, got %d", count)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		np := &NextProxy{ips: make(map[string]struct{})}
		np.AddIP("::1")
		if !np.ShouldProxy("::1") {
			t.Error("should proxy IPv6 after AddIP")
		}
	})
}

func TestAddDomain(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var np *NextProxy
		np.AddDomain("example.com") // should not panic
	})

	t.Run("添加域名", func(t *testing.T) {
		np := &NextProxy{domains: make(map[string]struct{})}
		np.AddDomain("cdn.example.com")
		if !np.ShouldProxy("cdn.example.com") {
			t.Error("should proxy after AddDomain")
		}
		// subdomain match should also work
		if !np.ShouldProxy("www.cdn.example.com") {
			t.Error("subdomain should also proxy after AddDomain")
		}
	})

	t.Run("去重", func(t *testing.T) {
		np := &NextProxy{domains: make(map[string]struct{})}
		np.AddDomain("cdn.example.com")
		np.AddDomain("cdn.example.com")
		count := 0
		np.mu.RLock()
		count = len(np.domains)
		np.mu.RUnlock()
		if count != 1 {
			t.Errorf("expected 1 domain, got %d", count)
		}
	})
}

func TestSubDomains(t *testing.T) {
	tests := []struct {
		input  string
		expect []string
	}{
		{"", nil},
		{"example.com", nil},
		{"www.example.com", []string{"example.com"}},
		{"a.b.example.com", []string{"b.example.com", "example.com"}},
		{"com", nil},
	}
	for _, tt := range tests {
		got := util.SubDomains(tt.input)
		if len(got) != len(tt.expect) {
			t.Errorf("subDomains(%q) = %v, want %v", tt.input, got, tt.expect)
			continue
		}
		for i := range got {
			if got[i] != tt.expect[i] {
				t.Errorf("subDomains(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.expect[i])
			}
		}
	}
}

func TestConcurrentAddIP(t *testing.T) {
	np := &NextProxy{ips: make(map[string]struct{})}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			np.AddIP("10.0.0.1")
			np.ShouldProxy("10.0.0.1")
		}
		done <- struct{}{}
	}()
	go func() {
		for i := 0; i < 100; i++ {
			np.AddIP("10.0.0.2")
			np.ShouldProxy("10.0.0.2")
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
