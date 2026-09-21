package main

import (
	"testing"

	"github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
)

// TestTunDNS 钉住 TUN 系统 DNS 的取值策略：
// 转发 DNS 启用时指向本机 127.0.0.1；否则使用本会话实测可达的解析器——
// 先内置直连 DNS，内置全不可用时用系统 DNS（DHCP/内网解析器），两者都没有
// 记录时回退到内置池第一个 IPv4 项（config.DefaultSystemDNS）。
func TestTunDNS(t *testing.T) {
	// 记录与熔断状态是包级变量，测试之间必须复位。
	easydns.ResetResolveState()
	t.Cleanup(easydns.ResetResolveState)

	cfg := config.DefaultConfig()

	cfg.Local.EnableForwardDNS = true
	if got := tunDNS(cfg); got != "127.0.0.1" {
		t.Fatalf("tunDNS(forward dns) = %q, want 127.0.0.1", got)
	}

	cfg.Local.EnableForwardDNS = false
	if got := tunDNS(cfg); got != config.DefaultSystemDNS {
		t.Fatalf("tunDNS(no forward dns, nothing recorded) = %q, want %q", got, config.DefaultSystemDNS)
	}

	// "全部内置 DNS 都不可用、只有 DHCP/内网解析器能用"的网络：系统 DNS 必须
	// 写那台确实可用的系统解析器，否则 TUN 会把已知不可达的内置地址写进系统，
	// 直连域名解析随之失败。
	easydns.MarkSystemServerReachable("192.168.1.1:53")
	if got := tunDNS(cfg); got != "192.168.1.1" {
		t.Fatalf("tunDNS(no forward dns, reachable system dns recorded) = %q, want 192.168.1.1", got)
	}

	// 启动/重试期的预解析成功过哪台内置服务器，系统 DNS 就用哪台（优先于系统
	// DNS）：写死池中第一项会在"第一项不可用、实际用的是别的内置 DNS"时不合理。
	easydns.MarkBuiltinServerReachable("119.29.29.29:53")
	if got := tunDNS(cfg); got != "119.29.29.29" {
		t.Fatalf("tunDNS(no forward dns, reachable builtin recorded) = %q, want 119.29.29.29", got)
	}
}
