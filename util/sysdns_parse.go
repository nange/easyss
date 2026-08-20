//go:build windows

package util

import "strings"

// parseDNSServersFromIPConfig parses the dns servers from the output of `ipconfig /all`.
//
// It matches the dns server section by label lines like "DNS Servers" or
// "DNS 服务器" (utf-8 or gbk encoded), then collects the following pure-ip
// lines as dns servers until the next non-empty non-ip line. The result is
// deduplicated and keeps the original order.
func parseDNSServersFromIPConfig(output string) []string {
	var ret []string
	seen := make(map[string]struct{})
	inDNSSection := false

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if isIPConfigDNSLabel(trimmed) {
			inDNSSection = true
			if idx := strings.IndexAny(trimmed, ":："); idx >= 0 {
				appendDNSIP(&ret, seen, strings.TrimSpace(trimmed[idx+1:]))
			}
			continue
		}
		if inDNSSection {
			if IsIP(trimmed) {
				appendDNSIP(&ret, seen, trimmed)
			} else if trimmed != "" {
				inDNSSection = false
			}
		}
	}

	return ret
}

func isIPConfigDNSLabel(line string) bool {
	if !strings.Contains(line, "DNS") {
		return false
	}

	// "DNS Servers" for english windows, "DNS 服务器" for chinese windows,
	// the latter may be utf-8 or gbk(cp936) encoded.
	return strings.Contains(line, "Servers") ||
		strings.Contains(line, "服务器") ||
		strings.Contains(line, "\xB7\xFE\xCE\xF1\xC6\xF7") // gbk encoding of 服务器
}

func appendDNSIP(ret *[]string, seen map[string]struct{}, ip string) {
	if !IsIP(ip) {
		return
	}
	if _, ok := seen[ip]; ok {
		return
	}
	seen[ip] = struct{}{}
	*ret = append(*ret, ip)
}
