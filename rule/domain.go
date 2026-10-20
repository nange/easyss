package rule

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/nange/easyss/v3/util"
)

// DomainSet 是只含域名的匹配集合：裸域名（含父域名匹配）、full: 精确匹配、regexp: 正则。
// 内置直连/屏蔽列表是纯域名数据，走 IP 解析会浪费启动时间，还会把 "1.2.3.4" 当成 IP。
type DomainSet struct {
	domains  map[string]struct{}
	full     map[string]struct{}
	patterns []*regexp.Regexp
}

// ParseDomainSet 解析内置/自定义 geosite 风格列表。无法编译的正则被跳过并计数返回
// （内置列表由发布流程生成，出错属于数据缺陷而不是用户配置错误）。
func ParseDomainSet(data []byte) (*DomainSet, int) {
	ds := &DomainSet{
		domains: make(map[string]struct{}),
		full:    make(map[string]struct{}),
	}
	var skipped int
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "full:"):
			ds.full[normalizeDomainKey(strings.TrimPrefix(trimmed, "full:"))] = struct{}{}
		case strings.HasPrefix(trimmed, "regexp:"):
			re, err := regexp.Compile("(?i)" + strings.TrimPrefix(trimmed, "regexp:"))
			if err != nil {
				skipped++
				continue
			}
			ds.patterns = append(ds.patterns, re)
		default:
			ds.domains[normalizeDomainKey(trimmed)] = struct{}{}
		}
	}
	return ds, skipped
}

// withSub 为 false 时只做精确匹配（含 full: 条目，不做父域名展开，也不算正则）；
// 屏蔽列表必须用 false，否则被屏蔽的父域名会把整棵子树都算进来。
func (ds *DomainSet) Match(domain string, withSub bool) bool {
	if ds == nil {
		return false
	}
	domain = NormalizeHost(domain)
	if domain == "" {
		return false
	}
	if _, ok := ds.full[domain]; ok {
		return true
	}
	if _, ok := ds.domains[domain]; ok {
		return true
	}
	if !withSub {
		return false
	}
	for _, sub := range util.SubDomains(domain) {
		if _, ok := ds.domains[sub]; ok {
			return true
		}
	}
	for _, re := range ds.patterns {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}

// Len 返回集合里的条目总数（不含正则）。
func (ds *DomainSet) Len() int {
	if ds == nil {
		return 0
	}
	return len(ds.domains) + len(ds.full) + len(ds.patterns)
}
