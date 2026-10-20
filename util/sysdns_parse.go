//go:build windows

package util

import "strings"

// 解析 `ipconfig /all` 的输出：DNS 条目以纯 IP 行续行，遇到非空且非 IP 的行即结束本段。
func parseDNSServersFromIPConfig(output string) []string {
	var ret []string
	seen := make(map[string]struct{})
	inDNSSection := false

	for line := range strings.SplitSeq(output, "\n") {
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

	// 英文版为 "DNS Servers"，中文版为 "DNS 服务器"，后者可能是 utf-8 或 gbk(cp936)。
	return strings.Contains(line, "Servers") ||
		strings.Contains(line, "服务器") ||
		strings.Contains(line, "\xB7\xFE\xCE\xF1\xC6\xF7") // "服务器" 的 gbk 编码
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
