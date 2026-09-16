//go:build windows

package util

import "strings"

// parseDNSServersFromIPConfig 从 `ipconfig /all` 的输出中解析 DNS 服务器。
//
// 它通过形如 "DNS Servers" 或 "DNS 服务器"（utf-8 或 gbk 编码）的标签行
// 定位 DNS 服务器段落，然后收集其后连续的纯 IP 行作为 DNS 服务器，直到
// 遇到下一个非空且非 IP 的行。结果会去重，
// 并保持原有顺序。
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

	// "DNS Servers" 用于英文版 Windows，"DNS 服务器" 用于中文版 Windows，
	// 后者可能是 utf-8 或 gbk(cp936) 编码。
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
