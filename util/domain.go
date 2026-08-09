package util

import (
	"regexp"
	"strings"
)

// GlobToRegexp converts a glob-like pattern (using * as wildcard) to a compiled
// regular expression. The * matches any sequence of characters. Anchors ^ and $
// are added so the pattern must match the entire input string.
func GlobToRegexp(pattern string) (*regexp.Regexp, error) {
	escaped := regexp.QuoteMeta(pattern)
	reStr := strings.ReplaceAll(escaped, `\*`, `.*`)
	return regexp.Compile(`^` + reStr + `$`)
}

// SubDomains returns all parent domains for subdomain matching.
// For "www.example.com", returns ["example.com"].
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
