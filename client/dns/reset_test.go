package dns

import "testing"

// TestResetResolveState 验证开机降级恢复所需的复位：内置 DNS 熔断状态与
// 系统 DNS 发现缓存都必须被清掉，否则"网络已恢复"会被拖后数分钟。
func TestResetResolveState(t *testing.T) {
	oldDiscover := sysDNSFunc
	oldSys := systemDNSServersFunc
	t.Cleanup(func() {
		sysDNSFunc = oldDiscover
		systemDNSServersFunc = oldSys
		ResetResolveState()
	})

	// 先清掉其他测试留下的共享状态，确保下面的发现一定被缓存。
	ResetResolveState()
	sysDNSFunc = func() ([]string, error) { return nil, nil }
	// 绕开可能存在的 indirection，直接触发一次发现。
	systemDNSServersFunc = SystemDNSServers
	if got := SystemDNSServers(); len(got) != 0 {
		t.Fatalf("SystemDNSServers = %v, want empty", got)
	}

	systemDNSMu.Lock()
	cachedAt := systemDNSTime
	systemDNSMu.Unlock()
	if cachedAt.IsZero() {
		t.Fatal("empty discovery result must be cached before the reset")
	}

	MarkBuiltinDNSUnavailable()

	ResetResolveState()

	if !BuiltinDNSAvailable() {
		t.Fatal("builtin dns servers must be retried after ResetResolveState")
	}

	systemDNSMu.Lock()
	cached, at := systemDNSCached, systemDNSTime
	systemDNSMu.Unlock()
	if cached != nil || !at.IsZero() {
		t.Fatalf("system dns discovery cache must be cleared, got %v / %v", cached, at)
	}
}
