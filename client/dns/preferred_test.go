package dns

import (
	"testing"

	"github.com/nange/easyss/v3/client/config"
)

// TestPreferredSystemDNSFallbackToDefault 验证内置与系统 DNS 都没有可达记录时，
// TUN 系统 DNS 回退到 config.DefaultSystemDNS（等于内置池第一个 IPv4 项，
// 由 client/config 的不变量测试钉住）。
func TestPreferredSystemDNSFallbackToDefault(t *testing.T) {
	clearReachableDNSServers()
	t.Cleanup(clearReachableDNSServers)

	if got := PreferredSystemDNS(); got != config.DefaultSystemDNS {
		t.Fatalf("PreferredSystemDNS = %q, want %q", got, config.DefaultSystemDNS)
	}
}

// TestPreferredSystemDNSUsesReachableBuiltin 验证取值优先使用本会话实测可达的
// 内置服务器，而不是回退值；非池成员（例如测试用的本地假服务器）被忽略。
func TestPreferredSystemDNSUsesReachableBuiltin(t *testing.T) {
	clearReachableDNSServers()
	t.Cleanup(clearReachableDNSServers)

	MarkBuiltinServerReachable("127.0.0.1:1")
	if got := PreferredSystemDNS(); got != config.DefaultSystemDNS {
		t.Fatalf("a non-pool server must not be recorded: PreferredSystemDNS = %q", got)
	}

	MarkBuiltinServerReachable("119.29.29.29:53")
	if got := PreferredSystemDNS(); got != "119.29.29.29" {
		t.Fatalf("PreferredSystemDNS = %q, want the reachable builtin 119.29.29.29", got)
	}
}

// TestPreferredSystemDNSUsesReachableSystemDNS 覆盖"全部内置 DNS 都不可用、
// 预解析落到系统 DNS 兜底"的网络：此时系统侧必须写那台确实能用的系统 DNS，
// 而不是回退到已知不可达的内置池首项。
func TestPreferredSystemDNSUsesReachableSystemDNS(t *testing.T) {
	clearReachableDNSServers()
	t.Cleanup(clearReachableDNSServers)

	MarkSystemServerReachable("192.168.1.1:53")
	if got := PreferredSystemDNS(); got != "192.168.1.1" {
		t.Fatalf("PreferredSystemDNS = %q, want the reachable system dns 192.168.1.1", got)
	}

	// 内置可达优先于系统可达：内置可用时不需要退回 DHCP/内网解析器。
	MarkBuiltinServerReachable("114.114.114.114:53")
	if got := PreferredSystemDNS(); got != "114.114.114.114" {
		t.Fatalf("PreferredSystemDNS = %q, want the reachable builtin 114.114.114.114", got)
	}
}

// TestPreferredSystemDNSIgnoresUnusableSystemDNS 验证写不进系统解析器配置的
// 系统 DNS 会被过滤：Linux 上 /etc/resolv.conf 常见 systemd-resolved 的 stub
// 127.0.0.53，写回去会让 resolved 把查询交给自己形成解析环；IPv6 地址在只有
// IPv4 的网络上不可用（TUN 的 IPv6 路由也只在服务端 IPv6 解析出来后才装）。
func TestPreferredSystemDNSIgnoresUnusableSystemDNS(t *testing.T) {
	clearReachableDNSServers()
	t.Cleanup(clearReachableDNSServers)

	for _, server := range []string{
		"127.0.0.53:53",
		"127.0.0.1:53",
		"0.0.0.0:53",
		"224.0.0.251:53",
		"[2402:4e00::]:53",
		"[fe80::1]:53",
	} {
		MarkSystemServerReachable(server)
		if got := PreferredSystemDNS(); got != config.DefaultSystemDNS {
			t.Errorf("PreferredSystemDNS = %q after marking unusable system dns %q, want %q",
				got, server, config.DefaultSystemDNS)
		}
	}
}

// TestPreferredSystemDNSIgnoresIPv6Builtin 验证内置项里的 IPv6 只取 IPv4。
func TestPreferredSystemDNSIgnoresIPv6Builtin(t *testing.T) {
	clearReachableDNSServers()
	t.Cleanup(clearReachableDNSServers)

	MarkBuiltinServerReachable("[2400:3200::1]:53")
	if got := PreferredSystemDNS(); got != config.DefaultSystemDNS {
		t.Fatalf("PreferredSystemDNS = %q, want the IPv4 fallback %q", got, config.DefaultSystemDNS)
	}
}

// TestResetResolveStateClearsPreferredDNS 验证网络状态变化后（ResetResolveState）
// 上一次网络里可用的服务器不再被当作当前可用。
func TestResetResolveStateClearsPreferredDNS(t *testing.T) {
	clearReachableDNSServers()
	t.Cleanup(clearReachableDNSServers)

	MarkSystemServerReachable("192.168.1.1:53")
	if got := PreferredSystemDNS(); got != "192.168.1.1" {
		t.Fatalf("PreferredSystemDNS = %q, want 192.168.1.1", got)
	}

	ResetResolveState()
	if got := PreferredSystemDNS(); got != config.DefaultSystemDNS {
		t.Fatalf("after ResetResolveState: PreferredSystemDNS = %q, want %q", got, config.DefaultSystemDNS)
	}
}

// TestPreferredSystemDNSEmptyPool 验证内置池为空（测试会替换该变量）时不 panic，
// 直接回退到 config.DefaultSystemDNS。
func TestPreferredSystemDNSEmptyPool(t *testing.T) {
	oldPool := config.DirectDNSServers
	config.DirectDNSServers = nil
	t.Cleanup(func() {
		config.DirectDNSServers = oldPool
		clearReachableDNSServers()
	})
	clearReachableDNSServers()

	if got := PreferredSystemDNS(); got != config.DefaultSystemDNS {
		t.Fatalf("PreferredSystemDNS = %q, want %q", got, config.DefaultSystemDNS)
	}
}
