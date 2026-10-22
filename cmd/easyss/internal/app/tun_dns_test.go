package app

import (
	"testing"

	clientconfig "github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
)

// TestTunDNS 钉住 TUN 系统 DNS 的取值策略：始终用本会话实测可达的解析器——内置直连 DNS
// 优先，全不可用才用系统 DNS（DHCP/内网解析器），都没记录则回退到
// clientconfig.DefaultSystemDNS。转发服务器只服务 LAN 设备，本机 TUN 指向 127.0.0.1 会绕开按
// 域名直连/代理的拆分，故与 enable_forward_dns 无关。
func TestTunDNS(t *testing.T) {
	t.Parallel()

	// 记录与熔断状态是包级变量，测试间必须复位。
	easydns.ResetResolveState()
	t.Cleanup(easydns.ResetResolveState)

	cfg := clientconfig.ClientConfig{}

	// 没有任何可达记录时回退到内置池第一个 IPv4 项。
	cfg.Local.EnableForwardDNS = false
	if got := tunDNS(); got != clientconfig.DefaultSystemDNS {
		t.Fatalf("tunDNS(forward dns off, nothing recorded) = %q, want %q", got, clientconfig.DefaultSystemDNS)
	}
	cfg.Local.EnableForwardDNS = true
	if got := tunDNS(); got != clientconfig.DefaultSystemDNS {
		t.Fatalf("tunDNS(forward dns on, nothing recorded) = %q, want %q", got, clientconfig.DefaultSystemDNS)
	}

	// 内置全不可用、只有内网解析器能用时，必须写那台可用的系统解析器：写进已知不可达
	// 的内置地址会让直连域名解析失败。
	easydns.MarkSystemServerReachable("192.168.1.1:53")
	if got := tunDNS(); got != "192.168.1.1" {
		t.Fatalf("tunDNS(forward dns on, reachable system dns recorded) = %q, want 192.168.1.1", got)
	}

	// 预解析成功过哪台内置服务器就用哪台（优先于系统 DNS）：写死池中第一项会在它
	// 不可用、实际用的是别的内置 DNS 时不成立。
	easydns.MarkBuiltinServerReachable("119.29.29.29:53")
	if got := tunDNS(); got != "119.29.29.29" {
		t.Fatalf("tunDNS(forward dns on, reachable builtin recorded) = %q, want 119.29.29.29", got)
	}
}
