package dns

import (
	"errors"
	"testing"
	"time"
)

// resetSystemDNSCache 清除缓存的系统 DNS 服务器，使测试注入的 sysDNSFunc
// 结果不会泄漏到其他测试。
func resetSystemDNSCache() {
	systemDNSMu.Lock()
	systemDNSCached = nil
	systemDNSTime = time.Time{}
	systemDNSMu.Unlock()
}

func TestSystemDNSServers(t *testing.T) {
	calls := 0
	old := sysDNSFunc
	sysDNSFunc = func() ([]string, error) {
		calls++
		return []string{"192.168.1.1", "2400:3200::1"}, nil
	}
	t.Cleanup(func() {
		sysDNSFunc = old
		resetSystemDNSCache()
	})

	got := SystemDNSServers()
	want := []string{"192.168.1.1:53", "[2400:3200::1]:53"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}

	// 结果已缓存：第二次调用不应重新发现
	SystemDNSServers()
	if calls != 1 {
		t.Fatalf("expected 1 discovery call, got %d", calls)
	}
}

func TestSystemDNSServersError(t *testing.T) {
	old := sysDNSFunc
	sysDNSFunc = func() ([]string, error) {
		return nil, errors.New("discovery failed")
	}
	t.Cleanup(func() {
		sysDNSFunc = old
		resetSystemDNSCache()
	})

	if got := SystemDNSServers(); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}
