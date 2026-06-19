package router

import (
	"testing"
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
		{"", ProxyRuleAuto},           // 空字符串默认 auto
		{"unknown", ProxyRuleAuto},    // 未知规则默认 auto
		{"Auto", ProxyRuleAuto},       // 大小写敏感 → 默认 auto
		{"PROXY", ProxyRuleAuto},      // 大小写敏感 → 默认 auto
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
		{"disable", IPV6RuleDisable},  // 显式 disable
		{"", IPV6RuleDisable},         // 空字符串默认 disable
		{"unknown", IPV6RuleDisable},  // 未知规则默认 disable
		{"Disable", IPV6RuleDisable},  // 大小写敏感 → 默认 disable
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
		{"example.com", nil},                                      // 只有一层子域名，排除顶级
		{"a.example.com", []string{"example.com"}},                // subs=[example.com, com] → len>1 → 去掉最后一个com
		{"b.a.example.com", []string{"a.example.com", "example.com"}},
		{"c.b.a.example.com", []string{"b.a.example.com", "a.example.com", "example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := subDomains(tt.domain)
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
		name          string
		ipv6Rule      IPV6Rule
		ipv6Networking bool
		serverIPV6    string
		want          bool
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
		{"www.baidu.cn", true},   // .cn 后缀
		{"example.cn", true},     // .cn 后缀
		{"www.baidu.com", true},  // geosite direct 列表匹配（如存在）
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
