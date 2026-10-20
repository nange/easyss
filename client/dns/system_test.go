package dns

import (
	"context"
	"errors"
	"testing"
	"time"
)

// systemServersFunc 让测试用一段函数替代系统 DNS 发现，不必构造带缓存的 systemDNS。
type systemServersFunc func() []string

func (f systemServersFunc) Servers() []string { return f() }

func TestSystemDNSServers(t *testing.T) {
	t.Parallel()

	calls := 0
	s := newSystemDNS(func() ([]string, error) {
		calls++
		return []string{"192.168.1.1", "2400:3200::1"}, nil
	})

	got := s.Servers()
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
	s.Servers()
	if calls != 1 {
		t.Fatalf("expected 1 discovery call, got %d", calls)
	}
}

func TestSystemDNSServersCachesEmptyResult(t *testing.T) {
	t.Parallel()

	calls := 0
	s := newSystemDNS(func() ([]string, error) {
		calls++
		return nil, nil
	})

	if got := s.Servers(); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
	s.Servers()
	if calls != 1 {
		t.Fatalf("an empty discovery result must be cached, got %d calls", calls)
	}
}

func TestSystemDNSServersError(t *testing.T) {
	t.Parallel()

	s := newSystemDNS(func() ([]string, error) {
		return nil, errors.New("discovery failed")
	})

	if got := s.Servers(); got != nil {
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
