package router

import (
	"regexp"
	"testing"

	"github.com/nange/easyss/v3/util"
)

func TestParseProxyRule(t *testing.T) {
	tests := []struct {
		input string
		want  ProxyRule
	}{
		{"auto", ProxyRuleAuto},
		{"reverse_auto", ProxyRuleReverseAuto},
		{"proxy", ProxyRuleProxy},
		{"direct", ProxyRuleDirect},
		{"auto_block", ProxyRuleAutoBlock},
		{"", ProxyRuleAuto},        // 空字符串默认 auto
		{"unknown", ProxyRuleAuto}, // 未知规则默认 auto
		{"Auto", ProxyRuleAuto},    // 大小写敏感 → 默认 auto
		{"PROXY", ProxyRuleAuto},   // 大小写敏感 → 默认 auto
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseProxyRule(tt.input)
			if got != tt.want {
				t.Errorf("ParseProxyRule(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseIPV6Rule(t *testing.T) {
	tests := []struct {
		input string
		want  IPV6Rule
	}{
		{"enable", IPV6RuleEnable},
		{"auto", IPV6RuleAuto},
		{"disable", IPV6RuleDisable}, // 显式 disable
		{"", IPV6RuleDisable},        // 空字符串默认 disable
		{"unknown", IPV6RuleDisable}, // 未知规则默认 disable
		{"Disable", IPV6RuleDisable}, // 大小写敏感 → 默认 disable
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseIPV6Rule(tt.input)
			if got != tt.want {
				t.Errorf("ParseIPV6Rule(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestSubDomains(t *testing.T) {
	tests := []struct {
		domain string
		want   []string
	}{
		{"", nil},
		{"com", nil},
		{"example.com", nil}, // 只有一层子域名，排除顶级
		{"a.example.com", []string{"example.com"}}, // subs=[example.com, com] → len>1 → 去掉最后一个com
		{"b.a.example.com", []string{"a.example.com", "example.com"}},
		{"c.b.a.example.com", []string{"b.a.example.com", "a.example.com", "example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := util.SubDomains(tt.domain)
			if len(got) != len(tt.want) {
				t.Errorf("subDomains(%q) = %v, want %v", tt.domain, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("subDomains(%q)[%d] = %q, want %q", tt.domain, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestNewGeoSite(t *testing.T) {
	data := []byte(`
example.com
full:www.example.com
regexp:^.*\.test\.com$
`)

	gs := NewGeoSite(data)
	if gs == nil {
		t.Fatal("NewGeoSite returned nil")
	}

	// 验证 domain 条目
	if _, ok := gs.domain["example.com"]; !ok {
		t.Error("expected example.com in domain map")
	}
	// 验证 full 条目
	if _, ok := gs.fullDomain["www.example.com"]; !ok {
		t.Error("expected www.example.com in fullDomain map")
	}
	// 验证 regexp 条目
	if len(gs.regexpDomain) != 1 {
		t.Fatalf("expected 1 regexp entry, got %d", len(gs.regexpDomain))
	}

	// 验证空行被跳过
	if len(gs.domain) != 1 {
		t.Errorf("expected 1 domain entry, got %d", len(gs.domain))
	}
}

func TestNewGeoSite_InvalidRegexp(t *testing.T) {
	// 无效正则表达式应被静默跳过
	data := []byte(`regexp:[invalid`)
	gs := NewGeoSite(data)
	if len(gs.regexpDomain) != 0 {
		t.Errorf("expected 0 regexp entries, got %d", len(gs.regexpDomain))
	}
}

func TestGeoSite_SimpleMatch(t *testing.T) {
	gs := NewGeoSite([]byte(`
example.com
full:exact.match.com
`))

	tests := []struct {
		name     string
		domain   string
		matchSub bool
		want     bool
	}{
		{"精确匹配 domain", "example.com", false, true},
		{"精确匹配 fullDomain", "exact.match.com", false, true},
		{"无匹配", "other.com", false, false},
		{"子域名匹配开启", "sub.example.com", true, true},
		{"子域名匹配关闭", "sub.example.com", false, false},
		{"仅子域名不匹配顶级", "example.com", true, true}, // 已精确匹配
		{"空域名", "", false, false},
		{"空域名+子域名匹配", "", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gs.SimpleMatch(tt.domain, tt.matchSub)
			if got != tt.want {
				t.Errorf("SimpleMatch(%q, %v) = %v, want %v", tt.domain, tt.matchSub, got, tt.want)
			}
		})
	}
}

func TestGeoSite_FullMatch(t *testing.T) {
	gs := NewGeoSite([]byte(`
example.com
full:exact.match.com
regexp:^sub\d+\.test\.com$
`))

	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"SimpleMatch 匹配", "example.com", true},
		{"SimpleMatch 子域名", "sub.example.com", true},
		{"fullDomain 匹配", "exact.match.com", true},
		{"regexp 匹配", "sub123.test.com", true},
		{"regexp 不匹配", "other.test.com", false},
		{"完全无匹配", "google.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gs.FullMatch(tt.domain)
			if got != tt.want {
				t.Errorf("FullMatch(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestNewRouter(t *testing.T) {
	// 验证 Router 可以用默认配置成功构造（使用嵌入式 GeoIP 数据）
	cfg := Config{
		ProxyRule:  ProxyRuleAuto,
		IPV6Rule:   IPV6RuleAuto,
		DirectFile: "",
		ProxyFile:  "",
	}

	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if r == nil {
		t.Fatal("New() returned nil")
	}
	if r.ProxyRule() != ProxyRuleAuto {
		t.Errorf("ProxyRule = %d, want %d", r.ProxyRule(), ProxyRuleAuto)
	}
}

func TestRouter_ShouldIPV6Disable(t *testing.T) {
	tests := []struct {
		name           string
		ipv6Rule       IPV6Rule
		ipv6Networking bool
		serverIPV6     string
		want           bool
	}{
		{"Enable 规则 → 不禁用", IPV6RuleEnable, false, "", false},
		{"Auto + 网络支持 + 服务端支持 → 不禁用", IPV6RuleAuto, true, "::1", false},
		{"Auto + 网络不支持 → 禁用", IPV6RuleAuto, false, "::1", true},
		{"Auto + 服务端不支持 → 禁用", IPV6RuleAuto, true, "", true},
		{"Disable 规则 → 禁用", IPV6RuleDisable, true, "::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Router{
				cfg: Config{
					IPV6Rule:       tt.ipv6Rule,
					IPV6NetWorking: tt.ipv6Networking,
					ServerIPV6:     tt.serverIPV6,
				},
			}
			r.ipv6Rule.Store(int32(tt.ipv6Rule))

			got := r.ShouldIPV6Disable()
			if got != tt.want {
				t.Errorf("ShouldIPV6Disable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRouter_SetProxyRule(t *testing.T) {
	r := &Router{}
	r.proxyRule.Store(int32(ProxyRuleAuto))

	r.SetProxyRule(ProxyRuleDirect)
	if r.ProxyRule() != ProxyRuleDirect {
		t.Errorf("ProxyRule = %d, want %d", r.ProxyRule(), ProxyRuleDirect)
	}
}

func TestRouter_SetIPV6Info(t *testing.T) {
	r := &Router{}
	r.SetIPV6Info(true, "2001:db8::1")

	if !r.cfg.IPV6NetWorking {
		t.Error("IPV6NetWorking should be true")
	}
	if r.cfg.ServerIPV6 != "2001:db8::1" {
		t.Errorf("ServerIPV6 = %q", r.cfg.ServerIPV6)
	}
	if r.ServerIPV6() != "2001:db8::1" {
		t.Errorf("ServerIPV6() = %q", r.ServerIPV6())
	}
}

func TestRouter_isLANHost(t *testing.T) {
	r := &Router{}

	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"8.8.8.8", false},
		{"example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := r.isLANHost(tt.host)
			if got != tt.want {
				t.Errorf("isLANHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestRouter_AddDirectIP(t *testing.T) {
	r := &Router{
		customDirectIPs: make(map[string]struct{}),
	}

	r.AddDirectIP("1.2.3.4")
	r.AddDirectIP("::1")

	r.customMu.RLock()
	defer r.customMu.RUnlock()
	if _, ok := r.customDirectIPs["1.2.3.4"]; !ok {
		t.Error("expected 1.2.3.4 in customDirectIPs")
	}
	if _, ok := r.customDirectIPs["::1"]; !ok {
		t.Error("expected ::1 in customDirectIPs")
	}
	if len(r.customDirectIPs) != 2 {
		t.Errorf("expected 2 entries, got %d", len(r.customDirectIPs))
	}
}

func TestRouter_AddProxyIP(t *testing.T) {
	r := &Router{
		customProxyIPs: make(map[string]struct{}),
	}

	r.AddProxyIP("10.0.0.1")
	r.AddProxyIP("fd00::1")

	r.customMu.RLock()
	defer r.customMu.RUnlock()
	if _, ok := r.customProxyIPs["10.0.0.1"]; !ok {
		t.Error("expected 10.0.0.1 in customProxyIPs")
	}
	if _, ok := r.customProxyIPs["fd00::1"]; !ok {
		t.Error("expected fd00::1 in customProxyIPs")
	}
	if len(r.customProxyIPs) != 2 {
		t.Errorf("expected 2 entries, got %d", len(r.customProxyIPs))
	}
}

func TestRouter_AddDirectDomain(t *testing.T) {
	r := &Router{
		customDirectDomains: make(map[string]struct{}),
	}

	r.AddDirectDomain("cdn.example.com")
	r.AddDirectDomain("cdn2.example.com")

	r.customMu.RLock()
	defer r.customMu.RUnlock()
	if _, ok := r.customDirectDomains["cdn.example.com"]; !ok {
		t.Error("expected cdn.example.com in customDirectDomains")
	}
	if _, ok := r.customDirectDomains["cdn2.example.com"]; !ok {
		t.Error("expected cdn2.example.com in customDirectDomains")
	}
	if len(r.customDirectDomains) != 2 {
		t.Errorf("expected 2 entries, got %d", len(r.customDirectDomains))
	}
}

func TestRouter_AddProxyDomain(t *testing.T) {
	r := &Router{
		customProxyDomains: make(map[string]struct{}),
	}

	r.AddProxyDomain("google.com")
	r.AddProxyDomain("youtube.com")

	r.customMu.RLock()
	defer r.customMu.RUnlock()
	if _, ok := r.customProxyDomains["google.com"]; !ok {
		t.Error("expected google.com in customProxyDomains")
	}
	if _, ok := r.customProxyDomains["youtube.com"]; !ok {
		t.Error("expected youtube.com in customProxyDomains")
	}
	if len(r.customProxyDomains) != 2 {
		t.Errorf("expected 2 entries, got %d", len(r.customProxyDomains))
	}
}

func TestRouter_IsCustomDirectDomain(t *testing.T) {
	r := &Router{
		customDirectDomains: map[string]struct{}{
			"example.com": {},
			"test.cn":     {},
		},
	}

	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"精确匹配", "example.com", true},
		{"精确匹配 .cn", "test.cn", true},
		{"子域名匹配", "sub.example.com", true},
		{"多层子域名匹配", "a.b.example.com", true},
		{"不匹配的域名", "other.com", false},
		{"部分匹配不算", "xample.com", false},
		{"空域名", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.IsCustomDirectDomain(tt.domain)
			if got != tt.want {
				t.Errorf("IsCustomDirectDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestRouter_IsCustomProxyDomain(t *testing.T) {
	r := &Router{
		customProxyDomains: map[string]struct{}{
			"google.com":  {},
			"youtube.com": {},
		},
	}

	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"精确匹配 google.com", "google.com", true},
		{"精确匹配 youtube.com", "youtube.com", true},
		{"子域名匹配", "mail.google.com", true},
		{"多层子域名匹配", "a.b.c.youtube.com", true},
		{"不匹配的域名", "facebook.com", false},
		{"空域名", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.IsCustomProxyDomain(tt.domain)
			if got != tt.want {
				t.Errorf("IsCustomProxyDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestRouter_AddIPAfterMatch(t *testing.T) {
	// 验证动态添加 IP 后，后续 MatchHostRule 可以基于 IP 匹配
	r := &Router{
		customDirectIPs:     make(map[string]struct{}),
		customDirectCIDRIPs: nil,
		customDirectDomains: nil,
		customProxyIPs:      make(map[string]struct{}),
		customProxyCIDRIPs:  nil,
		customProxyDomains:  nil,
	}
	r.proxyRule.Store(int32(ProxyRuleAuto))

	// 初始状态：IP 不在列表中
	if r.hostMatchCustomDirect("1.2.3.4") {
		t.Error("1.2.3.4 should not match before AddDirectIP")
	}
	if r.hostMatchCustomProxy("5.6.7.8") {
		t.Error("5.6.7.8 should not match before AddProxyIP")
	}

	// 动态添加
	r.AddDirectIP("1.2.3.4")
	r.AddProxyIP("5.6.7.8")

	// 添加后应匹配
	if !r.hostMatchCustomDirect("1.2.3.4") {
		t.Error("1.2.3.4 should match after AddDirectIP")
	}
	if !r.hostMatchCustomProxy("5.6.7.8") {
		t.Error("5.6.7.8 should match after AddProxyIP")
	}
}

func TestRouter_hostAtCN(t *testing.T) {
	// 构造带有内部 GeoIP 数据库的 Router（域名和 IP 判断）
	r, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host string
		want bool
	}{
		{"www.baidu.cn", true},    // .cn 后缀
		{"example.cn", true},      // .cn 后缀
		{"www.baidu.com", true},   // geosite direct 列表匹配（如存在）
		{"www.google.com", false}, // 国外域名
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := r.hostAtCN(tt.host)
			if got != tt.want {
				t.Errorf("hostAtCN(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestGlobToRegexp(t *testing.T) {
	tests := []struct {
		pattern string
		domain  string
		want    bool
	}{
		// *google* — 包含 google 的域名
		{"*google*", "google.com", true},
		{"*google*", "www.google.com", true},
		{"*google*", "mail.googleapis.com", true},
		{"*google*", "mygoogleapp.com", true},
		{"*google*", "facebook.com", false},
		// *.example.com — 子域名匹配
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "mail.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "notexample.com", false},
		// google* — 以 google 开头
		{"google*", "google.com", true},
		{"google*", "googleapis.com", true},
		{"google*", "mygoogle.com", false},
		// *.google.* — 包含 google 且两边有点
		{"*.google.*", "www.google.com", true},
		{"*.google.*", "api.google.hk", true},
		{"*.google.*", "google.com", false},
		{"*.google.*", "mygoogle.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.domain, func(t *testing.T) {
			re, err := globToRegexp(tt.pattern)
			if err != nil {
				t.Fatalf("globToRegexp(%q) error: %v", tt.pattern, err)
			}
			got := re.MatchString(tt.domain)
			if got != tt.want {
				t.Errorf("globToRegexp(%q).MatchString(%q) = %v, want %v", tt.pattern, tt.domain, got, tt.want)
			}
		})
	}
}

func TestRouter_RegexpAndGlobCustomDomain(t *testing.T) {
	// 构造 Router，仅测试自定义正则/通配符规则（不依赖文件读取）
	r := &Router{
		customDirectIPs:     make(map[string]struct{}),
		customDirectCIDRIPs: nil,
		customDirectDomains: make(map[string]struct{}),
		customDirectRegexps: nil,
		customProxyIPs:      make(map[string]struct{}),
		customProxyCIDRIPs:  nil,
		customProxyDomains:  make(map[string]struct{}),
		customProxyRegexps:  nil,
	}
	r.proxyRule.Store(int32(ProxyRuleAuto))

	// 手动添加 regexp 和 glob 规则（模拟 loadCustomIPDomains 的行为）
	directRe1, _ := regexp.Compile(`^.*\.baidu\.com$`) // regexp: 前缀
	directRe2, _ := globToRegexp("*taobao*")           // glob 通配符
	r.customDirectRegexps = append(r.customDirectRegexps, directRe1, directRe2)

	proxyRe1, _ := globToRegexp("*google*")            // glob 通配符
	proxyRe2, _ := regexp.Compile(`^.*\.youtube\..*$`) // regexp: 前缀
	r.customProxyRegexps = append(r.customProxyRegexps, proxyRe1, proxyRe2)

	// === 测试 hostMatchCustomDirect ===
	directTests := []struct {
		host string
		want bool
	}{
		{"www.baidu.com", true},
		{"tieba.baidu.com", true},
		{"api.taobao.com", true},
		{"www.taobao.com", true},
		{"mytaobaoapp.com", true},
		{"www.google.com", false},
		{"example.com", false},
	}
	for _, tt := range directTests {
		t.Run("direct/"+tt.host, func(t *testing.T) {
			got := r.hostMatchCustomDirect(tt.host)
			if got != tt.want {
				t.Errorf("hostMatchCustomDirect(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}

	// === 测试 hostMatchCustomProxy ===
	proxyTests := []struct {
		host string
		want bool
	}{
		{"www.google.com", true},
		{"mail.googleapis.com", true},
		{"mygoogleapp.com", true},
		{"www.youtube.com", true},
		{"music.youtube.com", true},
		{"www.baidu.com", false},
		{"example.com", false},
	}
	for _, tt := range proxyTests {
		t.Run("proxy/"+tt.host, func(t *testing.T) {
			got := r.hostMatchCustomProxy(tt.host)
			if got != tt.want {
				t.Errorf("hostMatchCustomProxy(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}

	// === 测试 IsCustomDirectDomain ===
	isDirectTests := []struct {
		domain string
		want   bool
	}{
		{"www.baidu.com", true},
		{"api.taobao.com", true},
		{"www.google.com", false},
		{"", false},
	}
	for _, tt := range isDirectTests {
		t.Run("IsDirect/"+tt.domain, func(t *testing.T) {
			got := r.IsCustomDirectDomain(tt.domain)
			if got != tt.want {
				t.Errorf("IsCustomDirectDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}

	// === 测试 IsCustomProxyDomain ===
	isProxyTests := []struct {
		domain string
		want   bool
	}{
		{"www.google.com", true},
		{"www.youtube.com", true},
		{"www.baidu.com", false},
		{"", false},
	}
	for _, tt := range isProxyTests {
		t.Run("IsProxy/"+tt.domain, func(t *testing.T) {
			got := r.IsCustomProxyDomain(tt.domain)
			if got != tt.want {
				t.Errorf("IsCustomProxyDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}

	// === 测试 MatchHostRule 正确集成 ===
	matchTests := []struct {
		host string
		want HostRule
	}{
		{"www.baidu.com", HostRuleDirect}, // 匹配 direct regexp
		{"www.google.com", HostRuleProxy}, // 匹配 proxy glob
	}
	for _, tt := range matchTests {
		t.Run("Match/"+tt.host, func(t *testing.T) {
			got := r.MatchHostRule(tt.host)
			if got != tt.want {
				t.Errorf("MatchHostRule(%q) = %d, want %d", tt.host, got, tt.want)
			}
		})
	}
}

func TestRouter_RegexpInvalidSkips(t *testing.T) {
	// 验证无效的正则表达式被静默跳过（与 NewGeoSite 行为一致）
	invalidRe, _ := regexp.Compile(`^valid$`) // 末尾加一个无效的不会被添加
	r := &Router{
		customDirectRegexps: []*regexp.Regexp{invalidRe},
		customDirectIPs:     make(map[string]struct{}),
		customDirectCIDRIPs: nil,
		customDirectDomains: make(map[string]struct{}),
		customProxyIPs:      make(map[string]struct{}),
		customProxyCIDRIPs:  nil,
		customProxyDomains:  make(map[string]struct{}),
		customProxyRegexps:  nil,
	}
	r.proxyRule.Store(int32(ProxyRuleAuto))

	// valid 正则应匹配
	if !r.hostMatchCustomDirect("valid") {
		t.Error("expected 'valid' to match")
	}
	// 无效的正则应不匹配
	if r.hostMatchCustomDirect("invalid") {
		t.Error("expected 'invalid' not to match")
	}
}
