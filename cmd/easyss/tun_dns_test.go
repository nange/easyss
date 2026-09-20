package main

import (
	"testing"

	"github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
)

// TestTunDNS 钉住 TUN 系统 DNS 的取值策略：
// 转发 DNS 启用时指向本机 127.0.0.1；否则使用本会话已确认可达的内置直连 DNS，
// 没有任何记录时回退到内置池第一个 IPv4 项（config.DefaultSystemDNS）。
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

	// 启动/重试期的预解析成功过哪台内置服务器，系统 DNS 就用哪台：
	// 写死池中第一项会在"第一项不可用、实际用的是别的内置 DNS"时不合理。
	easydns.MarkBuiltinServerReachable("119.29.29.29:53")
	if got := tunDNS(cfg); got != "119.29.29.29" {
		t.Fatalf("tunDNS(no forward dns, reachable builtin recorded) = %q, want 119.29.29.29", got)
	}
}
