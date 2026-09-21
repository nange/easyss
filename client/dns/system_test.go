package dns

import (
	"context"
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

// TestWithSystemDNSFallbackReserve 验证预算切分：只在 ctx 带截止时间且剩余预算
// 大于一个条目的预算时才把内置分支的截止时间提前，否则原样返回。
func TestWithSystemDNSFallbackReserve(t *testing.T) {
	oldItem := ResolveItemTimeout
	ResolveItemTimeout = 100 * time.Millisecond
	t.Cleanup(func() { ResolveItemTimeout = oldItem })

	// 无截止时间：不切分，返回同一个 context。
	noDeadline := context.Background()
	got, cancel := WithSystemDNSFallbackReserve(noDeadline)
	cancel()
	if got != noDeadline {
		t.Fatal("context without deadline must be returned unchanged")
	}

	// 剩余预算大于预留量：内置分支提前一个预留量截止。
	deadline := time.Now().Add(time.Second)
	parent, parentCancel := context.WithDeadline(context.Background(), deadline)
	defer parentCancel()
	got, cancel = WithSystemDNSFallbackReserve(parent)
	defer cancel()
	builtinDeadline, ok := got.Deadline()
	if !ok {
		t.Fatal("expected the builtin branch to have a deadline")
	}
	if left := time.Until(builtinDeadline); left > 950*time.Millisecond || left < 800*time.Millisecond {
		t.Fatalf("builtin deadline left %v, want about %v", left, time.Second-ResolveItemTimeout)
	}

	// 剩余预算不足预留量：不切分，交给原 ctx 约束。
	short, shortCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer shortCancel()
	got, cancel = WithSystemDNSFallbackReserve(short)
	defer cancel()
	if got != short {
		t.Fatal("context with a budget below the reserve must be returned unchanged")
	}
}
