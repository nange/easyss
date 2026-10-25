package dns

// 本文件的测试必须串行：内置 DNS 熔断、可达系统服务器记录与全局 logger 都是进程级状态，
// 并行测试会互相复位或串台。

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/log"
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

func fixedSystem(servers []string) func() []string {
	return func() []string { return servers }
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
	got, err := QueryWithBuiltinFirst([]string{"builtin"}, fixedSystem([]string{"system"}), try)
	if err != nil || got != reply {
		t.Fatalf("expected system reply, got %v, %v", got, err)
	}
	if builtinCalls != 1 || systemCalls != 1 {
		t.Fatalf("unexpected call counts: builtin=%d system=%d", builtinCalls, systemCalls)
	}

	// 冷却期内完全跳过内置服务器
	got, err = QueryWithBuiltinFirst([]string{"builtin"}, fixedSystem([]string{"system"}), try)
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
	got, err := QueryWithBuiltinFirst([]string{"builtin"}, fixedSystem([]string{"system"}), try)
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
	got, err := QueryWithBuiltinFirst(nil, fixedSystem([]string{"system"}), try)
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

	if _, err := QueryWithBuiltinFirst([]string{"builtin"}, fixedSystem(nil), try); err == nil {
		t.Fatal("expected error when every upstream fails")
	}
	if !BuiltinDNSAvailable() {
		t.Fatal("builtin dns must not be tripped when there is no fallback")
	}

	// 内置服务器必须继续被尝试，而不是在冷却期内被跳过
	if _, err := QueryWithBuiltinFirst([]string{"builtin"}, fixedSystem(nil), try); err == nil {
		t.Fatal("expected error when every upstream fails")
	}
	if builtinCalls != 2 {
		t.Fatalf("builtin should be retried without a fallback: builtin=%d", builtinCalls)
	}
}

// TestQueryWithBuiltinFirstArmedBreakerWithoutFallback 覆盖 F3：熔断可能是在
// "当时还有系统 DNS"的情况下置位的，之后兜底消失（Android 上系统 DNS 对应用
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

	got, err := QueryWithBuiltinFirst([]string{"builtin"}, fixedSystem(nil), try)
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

// TestBuiltinRouteFor 守住熔断判定必须是三个互斥状态：两个布尔会让"熔断中且没有兜底"
// 与"健康"在调用方看起来相同，于是"无视冷却重试"那条分支永远不可达。
func TestBuiltinRouteFor(t *testing.T) {
	MarkBuiltinDNSAvailable()
	t.Cleanup(MarkBuiltinDNSAvailable)

	for _, failover := range []bool{true, false} {
		if got := BuiltinRouteFor(func() bool { return failover }); got != BuiltinRouteFirst {
			t.Errorf("BuiltinRouteFor(failover=%v) with a healthy breaker = %v, want %v",
				failover, got, BuiltinRouteFirst)
		}
	}

	MarkBuiltinDNSUnavailable()
	if got := BuiltinRouteFor(func() bool { return true }); got != BuiltinRouteSkip {
		t.Errorf("armed breaker with a system failover = %v, want %v", got, BuiltinRouteSkip)
	}
	if got := BuiltinRouteFor(func() bool { return false }); got != BuiltinRouteRetry {
		t.Errorf("armed breaker without any failover = %v, want %v", got, BuiltinRouteRetry)
	}

	// 熔断器健康时不得求值 hasFailover：那是系统 DNS 发现（darwin 上走
	// networksetup，约 48ms），预解析不该为它付出代价。
	MarkBuiltinDNSAvailable()
	called := false
	BuiltinRouteFor(func() bool { called = true; return true })
	if called {
		t.Error("BuiltinRouteFor must not probe the system fallback while the breaker is healthy")
	}
}

// recordingHandler 记录所有日志记录，供"这条路径不得刷屏"这类断言使用。
type recordingHandler struct {
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) at(level slog.Level) []slog.Record {
	var out []slog.Record
	for _, r := range h.records {
		if r.Level == level {
			out = append(out, r)
		}
	}
	return out
}

// TestQueryWithBuiltinFirstRetryDoesNotWarn 守住日志级别与调用频率对应：QueryWithBuiltinFirst
// 每条 DNS 查询调用一次，Retry 态只能记 Debug，记 Warn 会按查询刷屏；低频预解析路径仍用 Warn。
func TestQueryWithBuiltinFirstRetryDoesNotWarn(t *testing.T) {
	resetBuiltinDNSCircuit()
	MarkBuiltinDNSUnavailable() // 熔断已置位
	t.Cleanup(resetBuiltinDNSCircuit)

	rec := &recordingHandler{}
	prev := log.Logger()
	log.SetLogger(slog.New(rec))
	t.Cleanup(func() { log.SetLogger(prev) })

	failure := errors.New("builtin unreachable")
	for range 3 {
		_, err := QueryWithBuiltinFirst(
			[]string{"192.0.2.1:53"},
			fixedSystem(nil), // 没有系统兜底 → BuiltinRouteRetry
			func([]string) (*dns.Msg, error) { return nil, failure },
		)
		if !errors.Is(err, failure) {
			t.Fatalf("QueryWithBuiltinFirst error = %v, want the builtin failure", err)
		}
	}

	if warns := rec.at(slog.LevelWarn); len(warns) != 0 {
		t.Fatalf("retry state produced %d Warn records over 3 queries, want 0: %v", len(warns), warns)
	}
	var retryDebugs int
	for _, r := range rec.at(slog.LevelDebug) {
		if strings.Contains(r.Message, "breaker is armed but no system dns") {
			retryDebugs++
		}
	}
	if retryDebugs != 3 {
		t.Fatalf("retry state produced %d retry-Debug records over 3 queries, want 3", retryDebugs)
	}
}

// 健康路径不能求值系统 DNS：ForwardServer 的兜底函数会枚举网卡过滤自环地址，
// 内置 DNS 成功时这次开销纯属浪费。
func TestQueryWithBuiltinFirstLazySystem(t *testing.T) {
	resetBuiltinDNSCircuit()
	reply := new(dns.Msg)
	var systemCalls int
	system := func() []string {
		systemCalls++
		return []string{"system"}
	}

	got, err := QueryWithBuiltinFirst([]string{"builtin"}, system, func(servers []string) (*dns.Msg, error) {
		if len(servers) != 1 || servers[0] != "builtin" {
			t.Fatalf("unexpected upstream list %v", servers)
		}
		return reply, nil
	})
	if err != nil || got != reply {
		t.Fatalf("builtin success: got %v, %v", got, err)
	}
	if systemCalls != 0 {
		t.Fatalf("system fallback evaluated %d times on the healthy path, want 0", systemCalls)
	}

	// 内置失败后只求值一次，判定有兜底与真正回退复用同一份列表。
	systemCalls = 0
	got, err = QueryWithBuiltinFirst([]string{"builtin"}, system, func(servers []string) (*dns.Msg, error) {
		if len(servers) == 1 && servers[0] == "builtin" {
			return nil, errors.New("builtin down")
		}
		if len(servers) == 1 && servers[0] == "system" {
			return reply, nil
		}
		t.Fatalf("unexpected upstream list %v", servers)
		return nil, nil
	})
	if err != nil || got != reply {
		t.Fatalf("system fallback: got %v, %v", got, err)
	}
	if systemCalls != 1 {
		t.Fatalf("system fallback evaluated %d times, want 1", systemCalls)
	}
}
