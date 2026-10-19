package rule

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/nange/easyss/v3/util"
)

// DomainSet 是只含域名的匹配集合，语义是 geosite 列表的那三种行：
//
//	example.com           域名（含所有父域名匹配）
//	full:www.example.com  精确匹配，不做父域名展开
//	regexp:^.+\.foo\.com$ 正则
//
// 它与 Set 的区别是**没有 IP/CIDR 条目**：内置直连/屏蔽列表是纯域名数据，
// 让它们走 IP 解析既浪费启动时间，也会把 "1.2.3.4" 这种并不存在的 TLD 规则
// 误当成 IP。两套列表的格式因此各自解析、共享同一份归一化与匹配语义。
type DomainSet struct {
	domains  map[string]struct{}
	full     map[string]struct{}
	patterns []*regexp.Regexp
}

// ParseDomainSet 解析内置/自定义 geosite 风格列表。无法编译的正则被跳过并
// 计数返回（内置列表由发布流程生成，出错属于数据缺陷而不是用户配置错误，
// 因此调用方通常只记一条启动日志）。
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
			ds.full[NormalizeHost(strings.TrimPrefix(trimmed, "full:"))] = struct{}{}
		case strings.HasPrefix(trimmed, "regexp:"):
			re, err := regexp.Compile("(?i)" + strings.TrimPrefix(trimmed, "regexp:"))
			if err != nil {
				skipped++
				continue
			}
			ds.patterns = append(ds.patterns, re)
		default:
			ds.domains[NormalizeHost(trimmed)] = struct{}{}
		}
	}
	return ds, skipped
}

// Match 报告 domain 是否命中集合。
//
// withSub 为 false 时只做精确匹配（含 full: 条目，但不做父域名展开，也不算
// 正则）——"这条域名本身是否被明确列出"；为 true 时再叠加父域名展开与
// regexp 模式，即"这个域名的任何一层是否被列入"。
//
// 这一对参数保留了 router 里 SimpleMatch(domain, matchSub) 与
// FullMatch(domain) 的既有语义：屏蔽列表用 withSub=false 是为了避免
// "某个被屏蔽的父域名"把整棵子树都算进来，而直连判定用 withSub=true。
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
