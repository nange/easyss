package dns

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// resetBuiltinDNSCircuit 清除内置 DNS 熔断器状态与可达记录（TUN 系统 DNS
// 的取值来源，含内置与系统两份），使各测试之间相互隔离。
func resetBuiltinDNSCircuit() {
	builtinDNSMu.Lock()
	builtinDNSDown = false
	builtinDNSDownAt = time.Time{}
	builtinDNSMu.Unlock()

	clearReachableDNSServers()
}

func TestBuiltinDNSAvailableInitial(t *testing.T) {
	resetBuiltinDNSCircuit()
	if !BuiltinDNSAvailable() {
		t.Fatal("builtin dns should be available initially")
	}
}

func TestBuiltinDNSUnavailableCoolDown(t *testing.T) {
	resetBuiltinDNSCircuit()
	MarkBuiltinDNSUnavailable()
	if BuiltinDNSAvailable() {
		t.Fatal("builtin dns should be skipped during cool-down")
	}

	// 模拟冷却期结束，此时允许一次重试
	builtinDNSMu.Lock()
	builtinDNSDownAt = time.Now().Add(-builtinDNSCoolDown)
	builtinDNSMu.Unlock()
	if !BuiltinDNSAvailable() {
		t.Fatal("builtin dns should be retried after cool-down")
	}

	// 恢复操作清除不可用状态
	MarkBuiltinDNSAvailable()
	if !BuiltinDNSAvailable() {
		t.Fatal("builtin dns should be available after recovery")
	}
}

func TestQueryWithBuiltinFirst(t *testing.T) {
	resetBuiltinDNSCircuit()
	reply := new(dns.Msg)
	var builtinCalls, systemCalls int
	try := func(servers []string) (*dns.Msg, error) {
		if len(servers) > 0 && servers[0] == "builtin" {
			builtinCalls++
			return nil, errors.New("builtin down")
		}
		systemCalls++
		return reply, nil
	}

	// 内置服务器查询失败，回退到系统 DNS 并标记熔断器
	got, err := QueryWithBuiltinFirst([]string{"builtin"}, []string{"system"}, try)
	if err != nil || got != reply {
		t.Fatalf("expected system reply, got %v, %v", got, err)
	}
	if builtinCalls != 1 || systemCalls != 1 {
		t.Fatalf("unexpected call counts: builtin=%d system=%d", builtinCalls, systemCalls)
	}

	// 冷却期内完全跳过内置服务器
	got, err = QueryWithBuiltinFirst([]string{"builtin"}, []string{"system"}, try)
	if err != nil || got != reply {
		t.Fatalf("expected system reply, got %v, %v", got, err)
	}
	if builtinCalls != 1 || systemCalls != 2 {
		t.Fatalf("builtin should be skipped during cool-down: builtin=%d system=%d", builtinCalls, systemCalls)
	}
}

func TestQueryWithBuiltinFirstRecoversAfterCoolDown(t *testing.T) {
	resetBuiltinDNSCircuit()
	MarkBuiltinDNSUnavailable()
	builtinDNSMu.Lock()
	builtinDNSDownAt = time.Now().Add(-builtinDNSCoolDown)
	builtinDNSMu.Unlock()

	reply := new(dns.Msg)
	try := func(servers []string) (*dns.Msg, error) {
		return reply, nil
	}
	got, err := QueryWithBuiltinFirst([]string{"builtin"}, []string{"system"}, try)
	if err != nil || got != reply {
		t.Fatalf("expected reply, got %v, %v", got, err)
	}
	if !BuiltinDNSAvailable() {
		t.Fatal("a successful builtin query should recover the breaker")
	}
}

func TestQueryWithBuiltinFirstEmptyBuiltin(t *testing.T) {
	resetBuiltinDNSCircuit()
	reply := new(dns.Msg)
	var systemCalls int
	try := func(servers []string) (*dns.Msg, error) {
		systemCalls++
		return reply, nil
	}
	got, err := QueryWithBuiltinFirst(nil, []string{"system"}, try)
	if err != nil || got != reply {
		t.Fatalf("expected system reply, got %v, %v", got, err)
	}
	if systemCalls != 1 {
		t.Fatalf("expected 1 system call, got %d", systemCalls)
	}
}

// TestQueryWithBuiltinFirstNoSystemFallback 验证没有系统 DNS 兜底时不会熔断
// 内置服务器：Android 上系统 DNS 对应用不可见，此时熔断会把 3 分钟冷却变成
// "每一次查询都立刻失败"的彻底解析中断。
func TestQueryWithBuiltinFirstNoSystemFallback(t *testing.T) {
	resetBuiltinDNSCircuit()
	var builtinCalls int
	try := func(servers []string) (*dns.Msg, error) {
		if len(servers) > 0 && servers[0] == "builtin" {
			builtinCalls++
		}
		return nil, errors.New("all dns servers down")
	}

	if _, err := QueryWithBuiltinFirst([]string{"builtin"}, nil, try); err == nil {
		t.Fatal("expected error when every upstream fails")
	}
	if !BuiltinDNSAvailable() {
		t.Fatal("builtin dns must not be tripped when there is no fallback")
	}

	// 内置服务器必须继续被尝试，而不是在冷却期内被跳过
	if _, err := QueryWithBuiltinFirst([]string{"builtin"}, nil, try); err == nil {
		t.Fatal("expected error when every upstream fails")
	}
	if builtinCalls != 2 {
		t.Fatalf("builtin should be retried without a fallback: builtin=%d", builtinCalls)
	}
}

// TestQueryWithBuiltinFirstArmedBreakerWithoutFallback 覆盖 F3：熔断可能是在
// "当时还有系统 DNS"的情况下置位的，随后兜底消失（Android 上系统 DNS 对应用
// 不可见）。此时必须无视冷却仍然尝试内置池，否则冷却期会变成彻底的解析中断。
func TestQueryWithBuiltinFirstArmedBreakerWithoutFallback(t *testing.T) {
	resetBuiltinDNSCircuit()
	MarkBuiltinDNSUnavailable()
	if BuiltinDNSAvailable() {
		t.Fatal("precondition: the breaker must be armed")
	}

	reply := new(dns.Msg)
	var builtinCalls int
	try := func(servers []string) (*dns.Msg, error) {
		if len(servers) > 0 && servers[0] == "builtin" {
			builtinCalls++
			return reply, nil
		}
		return nil, errors.New("system dns must not be consulted without a fallback")
	}

	got, err := QueryWithBuiltinFirst([]string{"builtin"}, nil, try)
	if err != nil || got != reply {
		t.Fatalf("expected the builtin reply, got %v, %v", got, err)
	}
	if builtinCalls != 1 {
		t.Fatalf("builtin calls = %d, want 1 (an armed breaker must be ignored without a fallback)", builtinCalls)
	}
	if !BuiltinDNSAvailable() {
		t.Fatal("a successful builtin query must clear the breaker")
	}
}

// TestBuiltinAttempt 固定熔断判定的两条规则：熔断未置位时总是应该试内置池；
// 已置位时只有"没有系统兜底"才仍然试（否则冷却期会变成彻底的中断）。
//
// 同时固定"只有存在兜底才熔断"这条共享规则——三条调用路径（并发竞争、串行带
// 预算、逐条目预算）都读它，把熔断判定收敛到一处的原因就在这里。
func TestBuiltinAttempt(t *testing.T) {
	MarkBuiltinDNSAvailable()
	t.Cleanup(MarkBuiltinDNSAvailable)

	for _, failover := range []bool{true, false} {
		try, arm := BuiltinAttempt(failover)
		if !try {
			t.Errorf("BuiltinAttempt(%v) with a healthy breaker = (false, _), want try", failover)
		}
		if arm != failover {
			t.Errorf("BuiltinAttempt(%v) arm = %v, want %v", failover, arm, failover)
		}
	}

	MarkBuiltinDNSUnavailable()
	if try, _ := BuiltinAttempt(true); try {
		t.Error("armed breaker with a system failover must skip the builtin pool")
	}
	if try, _ := BuiltinAttempt(false); !try {
		t.Error("armed breaker without any failover must still try the builtin pool")
	}
}
