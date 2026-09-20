package dns

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// resetBuiltinDNSCircuit 清除内置 DNS 熔断器状态与可达记录（TUN 系统 DNS
// 的取值来源），使各测试之间相互隔离。
func resetBuiltinDNSCircuit() {
	builtinDNSMu.Lock()
	builtinDNSDown = false
	builtinDNSDownAt = time.Time{}
	builtinDNSMu.Unlock()

	clearReachableBuiltinServers()
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
