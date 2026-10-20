package nextproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/rule"
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
		if got := np.Host(); got != "proxy.example.com:1080" {
			t.Errorf("Host = %q", got)
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

// newTestProxy 构造一个只带规则集合的 NextProxy（不拨号、不读文件），
// 规则行按生产路径解析，使测试覆盖的语义与运行时完全一致。
func newTestProxy(t *testing.T, lines ...string) *NextProxy {
	t.Helper()
	set, errs := rule.ParseLines(lines, rule.Options{AllowComments: true})
	if len(errs) != 0 {
		t.Fatalf("parse rules: %v", errs)
	}
	np := &NextProxy{}
	np.rules.Store(set)
	return np
}

// newEmptyTestProxy 构造一个规则集合为空、可直接学习的 NextProxy。
func newEmptyTestProxy() *NextProxy {
	np := &NextProxy{}
	np.rules.Store(rule.New())
	return np
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
		np := newTestProxy(t, "10.0.0.1")
		if !np.ShouldProxy("10.0.0.1") {
			t.Error("should proxy matching IP")
		}
		if np.ShouldProxy("10.0.0.2") {
			t.Error("should not proxy non-matching IP")
		}
	})

	t.Run("CIDR 匹配", func(t *testing.T) {
		np := newTestProxy(t, "192.168.0.0/16")
		if !np.ShouldProxy("192.168.1.1") {
			t.Error("should proxy CIDR-matching IP")
		}
		if np.ShouldProxy("10.0.0.1") {
			t.Error("should not proxy non-CIDR-matching IP")
		}
	})

	t.Run("域名匹配", func(t *testing.T) {
		np := newTestProxy(t, "example.com")
		if !np.ShouldProxy("example.com") {
			t.Error("should proxy matching domain")
		}
		if np.ShouldProxy("other.com") {
			t.Error("should not proxy non-matching domain")
		}
	})

	t.Run("子域名匹配", func(t *testing.T) {
		np := newTestProxy(t, "example.com")
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
		np := newTestProxy(t, "10.0.0.1", "example.com")
		if !np.ShouldProxy("10.0.0.1:8080") {
			t.Error("should proxy IP:port")
		}
		if !np.ShouldProxy("example.com:443") {
			t.Error("should proxy domain:port")
		}
	})

	t.Run("glob 模式匹配", func(t *testing.T) {
		np := newTestProxy(t, "*google*")
		if !np.ShouldProxy("www.google.com") {
			t.Error("should proxy glob-matching domain")
		}
		if !np.ShouldProxy("googleapis.com") {
			t.Error("should proxy glob-matching domain")
		}
		if np.ShouldProxy("facebook.com") {
			t.Error("should not proxy non-matching domain")
		}
	})

	t.Run("regexp 模式匹配", func(t *testing.T) {
		np := newTestProxy(t, `regexp:^.*\.youtube\..*$`)
		if !np.ShouldProxy("www.youtube.com") {
			t.Error("should proxy regexp-matching domain")
		}
		if np.ShouldProxy("youtube-not.com") {
			t.Error("should not proxy non-matching domain")
		}
	})

	// 大小写不敏感：DNS 名本身不区分大小写，规则匹配必须与之一致。
	t.Run("大小写不敏感", func(t *testing.T) {
		np := newTestProxy(t, "Example.COM", "*Google*")
		for _, host := range []string{"example.com", "EXAMPLE.COM", "www.Google.com"} {
			if !np.ShouldProxy(host) {
				t.Errorf("ShouldProxy(%q) = false, want true", host)
			}
		}
	})
}

func TestHost(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var np *NextProxy
		if got := np.Host(); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("正常返回", func(t *testing.T) {
		np, err := New("socks5://proxy.example.com:1080", false, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := np.Host(); got != "proxy.example.com:1080" {
			t.Errorf("Host = %q", got)
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

func TestLoadProxyFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "proxy.txt")
	content := `# comment
10.0.0.1
192.168.0.0/16
example.com
*google*
regexp:^.*\.youtube\..*$
`
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	np, err := New("socks5://proxy:1080", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := np.LoadProxyFile(file); err != nil {
		t.Fatal(err)
	}

	if !np.ShouldProxy("10.0.0.1") {
		t.Error("should proxy exact IP")
	}
	if !np.ShouldProxy("192.168.1.1") {
		t.Error("should proxy CIDR")
	}
	if !np.ShouldProxy("example.com") {
		t.Error("should proxy exact domain")
	}
	if !np.ShouldProxy("www.google.com") {
		t.Error("should proxy glob-matching domain")
	}
	if !np.ShouldProxy("www.youtube.com") {
		t.Error("should proxy regexp-matching domain")
	}
	if np.ShouldProxy("facebook.com") {
		t.Error("should not proxy unrelated domain")
	}
}

func TestIsCustomDomain(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var np *NextProxy
		if np.IsCustomDomain("example.com") {
			t.Error("nil receiver should return false")
		}
	})

	t.Run("精确匹配", func(t *testing.T) {
		np := newTestProxy(t, "example.com")
		if !np.IsCustomDomain("example.com") {
			t.Error("should match exact domain")
		}
	})

	t.Run("子域名匹配", func(t *testing.T) {
		np := newTestProxy(t, "example.com")
		if !np.IsCustomDomain("www.example.com") {
			t.Error("should match subdomain")
		}
		if !np.IsCustomDomain("api.example.com") {
			t.Error("should match subdomain")
		}
	})

	t.Run("不匹配", func(t *testing.T) {
		np := newTestProxy(t, "example.com")
		if np.IsCustomDomain("other.com") {
			t.Error("should not match unrelated domain")
		}
		if np.IsCustomDomain("not-example.com") {
			t.Error("should not match domain with different suffix")
		}
	})

	t.Run("glob 模式匹配", func(t *testing.T) {
		np := newTestProxy(t, "*google*")
		if !np.IsCustomDomain("www.google.com") {
			t.Error("should match glob pattern")
		}
		if np.IsCustomDomain("facebook.com") {
			t.Error("should not match unrelated domain")
		}
	})

	t.Run("regexp 模式匹配", func(t *testing.T) {
		np := newTestProxy(t, `regexp:^.*\.baidu\.com$`)
		if !np.IsCustomDomain("www.baidu.com") {
			t.Error("should match regexp pattern")
		}
		if np.IsCustomDomain("baidu.org") {
			t.Error("should not match unrelated domain")
		}
	})
}

func TestAddIP(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var np *NextProxy
		np.AddIP("1.2.3.4") // 不应 panic
	})

	t.Run("添加 IP", func(t *testing.T) {
		np := newEmptyTestProxy()
		np.AddIP("1.2.3.4")
		if !np.ShouldProxy("1.2.3.4") {
			t.Error("should proxy after AddIP")
		}
	})

	t.Run("去重", func(t *testing.T) {
		np := newEmptyTestProxy()
		np.AddIP("1.2.3.4")
		np.AddIP("1.2.3.4")
		if got := np.rules.Load().Len(); got != 1 {
			t.Errorf("expected 1 IP, got %d", got)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		np := newEmptyTestProxy()
		np.AddIP("::1")
		if !np.ShouldProxy("::1") {
			t.Error("should proxy IPv6 after AddIP")
		}
	})

	// 学习路径写入 IPv4-mapped 形式时必须与拨号目标的 IPv4 字面量匹配
	// （两边的归一化必须对称）。
	t.Run("IPv4-mapped 归一化", func(t *testing.T) {
		np := newEmptyTestProxy()
		np.AddIP("::ffff:1.2.3.4")
		if !np.ShouldProxy("1.2.3.4") {
			t.Error("IPv4-mapped learned IP should match the plain IPv4 target")
		}
	})

	// 学习预算必须有界：超过 maxLearnedEntries 后不再增长。
	t.Run("学习预算有界", func(t *testing.T) {
		np := newEmptyTestProxy()
		for i := range maxLearnedEntries + 10 {
			np.AddIP(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
		}
		if got := np.learnedIPs; got != maxLearnedEntries {
			t.Errorf("learnedIPs = %d, want %d", got, maxLearnedEntries)
		}
	})
}

func TestAddDomain(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var np *NextProxy
		np.AddDomain("example.com") // 不应 panic
	})

	t.Run("添加域名", func(t *testing.T) {
		np := newEmptyTestProxy()
		np.AddDomain("cdn.example.com")
		if !np.ShouldProxy("cdn.example.com") {
			t.Error("should proxy after AddDomain")
		}
		// 子域名匹配也应生效
		if !np.ShouldProxy("www.cdn.example.com") {
			t.Error("subdomain should also proxy after AddDomain")
		}
	})

	t.Run("去重", func(t *testing.T) {
		np := newEmptyTestProxy()
		np.AddDomain("cdn.example.com")
		np.AddDomain("cdn.example.com")
		if got := np.rules.Load().Len(); got != 1 {
			t.Errorf("expected 1 domain, got %d", got)
		}
	})

	t.Run("大小写归一化", func(t *testing.T) {
		np := newEmptyTestProxy()
		np.AddDomain("CDN.Example.COM")
		if !np.ShouldProxy("cdn.example.com") {
			t.Error("learned domain should be normalized to lower case")
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
	np := newEmptyTestProxy()
	done := make(chan struct{})
	go func() {
		for range 100 {
			np.AddIP("10.0.0.1")
			np.ShouldProxy("10.0.0.1")
		}
		done <- struct{}{}
	}()
	go func() {
		for range 100 {
			np.AddIP("10.0.0.2")
			np.ShouldProxy("10.0.0.2")
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
