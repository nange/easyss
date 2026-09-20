package dns

import (
	"testing"

	"github.com/nange/easyss/v3/client/config"
)

// TestPreferredSystemDNSFallbackToFirstIPv4 验证还没有任何内置服务器应答过时，
// TUN 系统 DNS 回退到内置池第一个 IPv4 项（config.DefaultSystemDNS）。
func TestPreferredSystemDNSFallbackToFirstIPv4(t *testing.T) {
	clearReachableBuiltinServers()
	t.Cleanup(clearReachableBuiltinServers)

	if got := PreferredSystemDNS(); got != config.DefaultSystemDNS {
		t.Fatalf("PreferredSystemDNS = %q, want %q", got, config.DefaultSystemDNS)
	}
}

// TestPreferredSystemDNSUsesReachableBuiltin 验证取值优先使用本会话实测可达的
// 内置服务器，而不是写死池中第一项；非池成员（例如测试用的本地假服务器）被忽略。
func TestPreferredSystemDNSUsesReachableBuiltin(t *testing.T) {
	clearReachableBuiltinServers()
	t.Cleanup(clearReachableBuiltinServers)

	MarkBuiltinServerReachable("127.0.0.1:1")
	if got := PreferredSystemDNS(); got != config.DefaultSystemDNS {
		t.Fatalf("a non-pool server must not be recorded: PreferredSystemDNS = %q", got)
	}

	MarkBuiltinServerReachable("119.29.29.29:53")
	if got := PreferredSystemDNS(); got != "119.29.29.29" {
		t.Fatalf("PreferredSystemDNS = %q, want the reachable builtin 119.29.29.29", got)
	}
}

// TestPreferredSystemDNSIgnoresIPv6 验证只取 IPv4：TUN 的 IPv6 路由仅在服务端
// IPv6 解析出来后才安装，把 IPv6 解析器写进系统配置在只有 IPv4 的网络上不可用。
func TestPreferredSystemDNSIgnoresIPv6(t *testing.T) {
	clearReachableBuiltinServers()
	t.Cleanup(clearReachableBuiltinServers)

	MarkBuiltinServerReachable("[2400:3200::1]:53")
	if got := PreferredSystemDNS(); got != config.DefaultSystemDNS {
		t.Fatalf("PreferredSystemDNS = %q, want the IPv4 fallback %q", got, config.DefaultSystemDNS)
	}
}

// TestResetResolveStateClearsPreferredBuiltin 验证网络状态变化后（ResetResolveState）
// 上一次网络里可用的服务器不再被当作当前可用。
func TestResetResolveStateClearsPreferredBuiltin(t *testing.T) {
	clearReachableBuiltinServers()
	t.Cleanup(clearReachableBuiltinServers)

	MarkBuiltinServerReachable("114.114.114.114:53")
	if got := PreferredSystemDNS(); got != "114.114.114.114" {
		t.Fatalf("PreferredSystemDNS = %q, want 114.114.114.114", got)
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
		clearReachableBuiltinServers()
	})
	clearReachableBuiltinServers()

	if got := PreferredSystemDNS(); got != config.DefaultSystemDNS {
		t.Fatalf("PreferredSystemDNS = %q, want %q", got, config.DefaultSystemDNS)
	}
}
