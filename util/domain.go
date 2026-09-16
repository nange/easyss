package util

import (
	"regexp"
	"strings"
)

// GlobToRegexp 将类似 glob 的模式（使用 * 作为通配符）转换为编译好的
// 正则表达式。* 匹配任意字符序列。会加上 ^ 和 $ 锚点，
// 因此模式必须匹配整个输入字符串。
func GlobToRegexp(pattern string) (*regexp.Regexp, error) {
	escaped := regexp.QuoteMeta(pattern)
	reStr := strings.ReplaceAll(escaped, `\*`, `.*`)
	return regexp.Compile(`^` + reStr + `$`)
}

// SubDomains 返回用于子域名匹配的所有父级域名。
// 例如 "www.example.com" 返回 ["example.com"]。
func SubDomains(domain string) []string {
	if domain == "" {
		return nil
	}
	subs := make([]string, 0, 8)
	i := strings.Index(domain, ".")
	for i > 0 {
		domain = domain[i+1:]
		subs = append(subs, domain)
		i = strings.Index(domain, ".")
	}
	if len(subs) > 1 {
		return subs[:len(subs)-1]
	}
	return nil
}
