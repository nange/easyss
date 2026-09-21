package config

import (
	"net"
	"slices"
	"testing"
)

// TestDirectDNSServersInvariants 钉住内置直连 DNS 池的两条不变量：
// 每项都是端口 53 的 host:port；IPv4 项全部排在 IPv6 项之前（顺序是服务端
// 域名串行预解析的优先级依据）。同时锁定用户明确要求新增的两台解析器。
func TestDirectDNSServersInvariants(t *testing.T) {
	firstIPv4 := ""
	seenIPv6 := false

	for _, addr := range DirectDNSServers {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("DirectDNSServers entry %q is not host:port: %v", addr, err)
		}
		if port != "53" {
			t.Errorf("DirectDNSServers entry %q uses port %q, want 53", addr, port)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			t.Fatalf("DirectDNSServers entry %q has an unparsable host %q", addr, host)
		}
		if ip.To4() != nil {
			if seenIPv6 {
				t.Errorf("IPv4 entry %q must not follow an IPv6 entry", addr)
			}
			if firstIPv4 == "" {
				firstIPv4 = host
			}
			continue
		}
		seenIPv6 = true
	}

	for _, want := range []string{"114.114.114.114:53", "123.123.123.123:53"} {
		if !slices.Contains(DirectDNSServers, want) {
			t.Errorf("DirectDNSServers is missing %q", want)
		}
	}

	if firstIPv4 != DefaultSystemDNS {
		t.Errorf("DefaultSystemDNS = %q, want the first IPv4 entry %q", DefaultSystemDNS, firstIPv4)
	}
}
