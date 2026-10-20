package dns

// 本文件的测试必须串行：ResetResolveState 清的是包级 defaultSystemDNS 缓存与内置熔断，
// 并行测试看到的会是别人复位后的状态。

import (
	"testing"
	"time"
)

// TestResetResolveState 验证开机降级恢复所需的复位：内置 DNS 熔断状态、可达记录与
// 系统 DNS 发现缓存都必须被清掉，否则"网络已恢复"会被拖后数分钟。
func TestResetResolveState(t *testing.T) {
	MarkBuiltinDNSUnavailable()
	MarkSystemServerReachable("192.0.2.1:53")
	defaultSystemDNS.mu.Lock()
	defaultSystemDNS.cached = []string{"192.0.2.1:53"}
	defaultSystemDNS.at = time.Now()
	defaultSystemDNS.mu.Unlock()
	t.Cleanup(ResetResolveState)

	ResetResolveState()

	if !BuiltinDNSAvailable() {
		t.Fatal("builtin dns servers must be retried after ResetResolveState")
	}

	defaultSystemDNS.mu.Lock()
	cached, at := defaultSystemDNS.cached, defaultSystemDNS.at
	defaultSystemDNS.mu.Unlock()
	if cached != nil || !at.IsZero() {
		t.Fatalf("system dns discovery cache must be cleared, got %v / %v", cached, at)
	}

	reachableDNSMu.Lock()
	builtin, system := len(reachableBuiltinDNS), len(reachableSystemDNS)
	reachableDNSMu.Unlock()
	if builtin != 0 || system != 0 {
		t.Fatalf("reachable records must be cleared, got %d builtin / %d system", builtin, system)
	}
}
