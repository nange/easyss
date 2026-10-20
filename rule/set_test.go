package rule

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp rule file: %v", err)
	}
	return path
}

// TestParseLinesKinds 固定每类规则的识别结果与计数：解析优先级是 README 的
// 公开契约（regexp: → glob → CIDR → IP → 域名）。
func TestParseLinesKinds(t *testing.T) {
	set, errs := ParseLines([]string{
		"example.com",
		"1.2.3.4",
		"10.0.0.0/8",
		"*google*",
		`regexp:^.*\.cdn\.example$`,
		"",
		"# 整行注释",
	}, Options{AllowComments: true})
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %v", errs)
	}

	domains, ips, cidrs, patterns := set.Counts()
	if domains != 1 || ips != 1 || cidrs != 1 || patterns != 2 {
		t.Fatalf("Counts() = (%d,%d,%d,%d), want (1,1,1,2)", domains, ips, cidrs, patterns)
	}
	if set.Len() != 5 {
		t.Fatalf("Len() = %d, want 5", set.Len())
	}
}

// TestParseLinesReportsErrors 固定"不再静默失败"：无法编译的正则必须带行号
// 上报，并且不影响其余规则的加载。
func TestParseLinesReportsErrors(t *testing.T) {
	set, errs := ParseLines([]string{
		"ok.example",
		`regexp:[invalid`,
		"another.example",
	}, Options{})
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want exactly one", errs)
	}
	if errs[0].Index != 1 {
		t.Errorf("errs[0].Index = %d, want 1", errs[0].Index)
	}
	if !strings.Contains(errs[0].Error(), "line 2") {
		t.Errorf("error text %q should name the line number", errs[0].Error())
	}
	if !set.MatchHost("ok.example") || !set.MatchHost("another.example") {
		t.Error("valid rules should still be loaded when another line fails")
	}
}

// TestMatchHostDomainSemantics 固定域名匹配语义：自身、父域名、glob、regexp，
// 以及"父域名展开不会匹配到顶级标签"。
func TestMatchHostDomainSemantics(t *testing.T) {
	set, errs := ParseLines([]string{
		"example.com",
		"*.cdn.example.org",
		`regexp:^ads\d+\.tracker\.net$`,
	}, Options{})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"deep.a.example.com", true},
		{"notexample.com", false},
		{"x.cdn.example.org", true},
		{"cdn.example.org", false},
		{"ads12.tracker.net", true},
		{"ads.tracker.net", false},
		{"", false},
	}
	for _, tt := range cases {
		if got := set.MatchHost(tt.host); got != tt.want {
			t.Errorf("MatchHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

// TestMatchHostIsCaseInsensitive 固定 DNS 名大小写不敏感：匹配必须与之一致，
// 否则同一条查询会按大小写得到不同路由。
func TestMatchHostIsCaseInsensitive(t *testing.T) {
	set, _ := ParseLines([]string{
		"Example.COM",
		"*Google*",
		`regexp:^Ads\d+\.Tracker\.NET$`,
	}, Options{})

	for _, host := range []string{
		"example.com", "EXAMPLE.COM", "Www.Example.Com",
		"www.google.com", "WWW.GOOGLE.COM",
		"ads7.tracker.net", "ADS7.TRACKER.NET",
	} {
		if !set.MatchHost(host) {
			t.Errorf("MatchHost(%q) = false, want true (case-insensitive)", host)
		}
	}
}

// TestMatchHostStripsPortAndTrailingDot 固定 host 归一化：调用方可能传带端口
// 的目标或 FQDN 形式的 qname，两者必须与裸域名得到同一结论。
func TestMatchHostStripsPortAndTrailingDot(t *testing.T) {
	set, _ := ParseLines([]string{"example.com", "1.2.3.4", "10.0.0.0/8"}, Options{})

	for _, host := range []string{
		"example.com",
		"example.com.",
		"example.com:443",
		"EXAMPLE.COM:8443",
		"sub.example.com:80",
	} {
		if !set.MatchHost(host) {
			t.Errorf("MatchHost(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"1.2.3.4", "1.2.3.4:53", "[::ffff:1.2.3.4]", "10.9.8.7"} {
		if !set.MatchHost(host) {
			t.Errorf("MatchHost(%q) = false, want true", host)
		}
	}
}

// TestMatchHostIPv4Mapped 固定 IP 归一化的对称性：学习路径写入 IPv4-mapped
// 形式时，必须与拨号目标里的 IPv4 字面量匹配（两边的归一化必须对称）。
func TestMatchHostIPv4Mapped(t *testing.T) {
	set := New()
	set.AddIP("::ffff:1.2.3.4")
	if !set.MatchHost("1.2.3.4") {
		t.Error("IPv4-mapped entry should match the plain IPv4 host")
	}

	parsed, errs := ParseLines([]string{"::ffff:5.6.7.8"}, Options{})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if !parsed.MatchHost("5.6.7.8") {
		t.Error("IPv4-mapped literal in a rule file should match the plain IPv4 host")
	}
}

// TestAddIPAndDomainAreIdempotent 固定学习路径的幂等性：重复加入同一条目不会
// 重复计数（计数用于启动日志与学习预算）。
func TestAddIPAndDomainAreIdempotent(t *testing.T) {
	set := New()
	set.AddIP("1.2.3.4")
	set.AddIP("1.2.3.4")
	set.AddIP("::ffff:1.2.3.4")
	set.AddDomain("Example.com")
	set.AddDomain("example.com")

	domains, ips, _, _ := set.Counts()
	if domains != 1 {
		t.Errorf("domains = %d, want 1", domains)
	}
	if ips != 1 {
		t.Errorf("ips = %d, want 1", ips)
	}
}

// TestHasDomainIgnoresIPShape 固定 HasDomain 与 MatchHost 的分工：前者绝不按
// IP 处理，因此"长得像 IP 的域名"不会被误判成 IP 命中。
func TestHasDomainIgnoresIPShape(t *testing.T) {
	set, _ := ParseLines([]string{"1.2.3.4"}, Options{})
	if !set.MatchHost("1.2.3.4") {
		t.Fatal("MatchHost should match the IP entry")
	}
	if set.HasDomain("1.2.3.4") {
		t.Error("HasDomain must not treat an IP literal as a domain")
	}
}

// TestNilSet 固定 nil 接收者的安全性：router 与 nextproxy 都允许"未配置"。
func TestNilSet(t *testing.T) {
	var set *Set
	if set.MatchHost("example.com") || set.HasDomain("example.com") {
		t.Error("nil Set must never match")
	}
	set.AddIP("1.2.3.4") // 不应 panic
	set.AddDomain("x")
	if set.Len() != 0 {
		t.Error("nil Set must report zero length")
	}
}

// TestParseFile 固定文件解析：路径为空返回空集；文件不存在返回错误；行级错误
// 由 FileError 汇总并带上文件名。
func TestParseFile(t *testing.T) {
	t.Run("空路径", func(t *testing.T) {
		set, errs, err := ParseFile("", Options{})
		if err != nil || len(errs) != 0 || set.Len() != 0 {
			t.Fatalf("ParseFile(\"\") = (%v, %v, %v)", set, errs, err)
		}
	})

	t.Run("文件不存在", func(t *testing.T) {
		_, _, err := ParseFile(filepath.Join(t.TempDir(), "missing.txt"), Options{})
		if err == nil {
			t.Fatal("expected an error for a missing rule file")
		}
	})

	t.Run("行级错误汇总", func(t *testing.T) {
		path := writeTempFile(t, "bad.example\nregexp:[oops\nregexp:(unclosed\n")
		set, errs, err := ParseFile(path, Options{})
		if err != nil {
			t.Fatalf("ParseFile: %v", err)
		}
		if len(errs) != 2 {
			t.Fatalf("errs = %d, want 2", len(errs))
		}
		if !set.MatchHost("bad.example") {
			t.Error("valid rule should still be loaded")
		}
		joined := FileError(path, errs)
		if joined == nil || !strings.Contains(joined.Error(), "rules.txt") {
			t.Fatalf("FileError = %v, want it to name the file", joined)
		}
	})

	t.Run("行尾注释不被截断", func(t *testing.T) {
		// 行尾注释不是支持的语法：'#' 在正则/glob 里可能合法，截断会把一条
		// 有效规则改写成另一条。这里固定"原样当成规则处理"的行为。
		path := writeTempFile(t, "example.com # comment\n")
		set, _, err := ParseFile(path, Options{AllowComments: true})
		if err != nil {
			t.Fatalf("ParseFile: %v", err)
		}
		if set.MatchHost("example.com") {
			t.Error("an inline comment must not silently produce a matching rule")
		}
	})
}

// TestParseDomainSet 固定 geosite 风格列表（内置直连/屏蔽列表）的解析与匹配。
func TestParseDomainSet(t *testing.T) {
	ds, skipped := ParseDomainSet([]byte(`
example.com
full:exact.other.net
regexp:^sub\d+\.pattern\.com$
# 注释
regexp:[broken
`))
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}

	cases := []struct {
		domain  string
		withSub bool
		want    bool
	}{
		{"example.com", false, true},
		{"sub.example.com", false, false}, // 不做父域名展开
		{"sub.example.com", true, true},
		{"exact.other.net", false, true},
		{"x.exact.other.net", true, false}, // full: 条目自身不做父域名展开
		{"sub42.pattern.com", true, true},
		{"sub42.pattern.com", false, false}, // 正则只在 withSub 时参与
		{"EXAMPLE.COM", true, true},
		{"other.com", true, false},
		{"", true, false},
	}
	for _, tt := range cases {
		if got := ds.Match(tt.domain, tt.withSub); got != tt.want {
			t.Errorf("Match(%q, %v) = %v, want %v", tt.domain, tt.withSub, got, tt.want)
		}
	}
}

// TestParseDomainSetNil 固定 nil 接收者语义（未配置的内置列表）。
func TestParseDomainSetNil(t *testing.T) {
	var ds *DomainSet
	if ds.Match("example.com", true) {
		t.Error("nil DomainSet must never match")
	}
	if ds.Len() != 0 {
		t.Error("nil DomainSet must report zero length")
	}
}

// TestNormalizeHost 固定归一化本身：端口、方括号、尾部点号、大小写。
func TestNormalizeHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"example.com", "example.com"},
		{"Example.COM.", "example.com"},
		{"example.com:443", "example.com"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"1.2.3.4:53", "1.2.3.4"},
	}
	for _, tt := range cases {
		if got := NormalizeHost(tt.in); got != tt.want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestCanonicalIP 固定 IP 规范形式：IPv4 与 IPv4-mapped 折叠成同一字符串。
func TestCanonicalIP(t *testing.T) {
	for _, ip := range []string{"1.2.3.4", "::ffff:1.2.3.4"} {
		if got := canonicalIP(net.ParseIP(ip)); got != "1.2.3.4" {
			t.Errorf("canonicalIP(%q) = %q, want 1.2.3.4", ip, got)
		}
	}
	if got := canonicalIP(net.ParseIP("2001:db8::1")); got != "2001:db8::1" {
		t.Errorf("canonicalIP(IPv6) = %q", got)
	}
}
