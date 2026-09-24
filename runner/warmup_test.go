package runner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/transport"
)

// warmUpTestTransport 是最小的 transport.Transport 桩：记录预热/打开调用次数、
// 可注入预热错误，并记录预热 context 的截止时间，使 warmUpTransport 的契约
// （调用一次、透传错误、零超时回退默认值）无需任何真实网络即可断言。
type warmUpTestTransport struct {
	mu             sync.Mutex
	warmUpCount    int
	openCount      int
	warmUpErr      error
	warmUpDeadline time.Time
}

func (t *warmUpTestTransport) Open(context.Context, transport.OpenRequest) (transport.Stream, error) {
	t.mu.Lock()
	t.openCount++
	t.mu.Unlock()
	return nil, errors.New("open must not be called by the warm-up")
}

func (t *warmUpTestTransport) WarmUp(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.warmUpCount++
	if deadline, ok := ctx.Deadline(); ok {
		t.warmUpDeadline = deadline
	}
	return t.warmUpErr
}

func (t *warmUpTestTransport) CloseIdle() {}

func (t *warmUpTestTransport) Stats() transport.TransportStats { return transport.TransportStats{} }

func (t *warmUpTestTransport) Close() error { return nil }

func (t *warmUpTestTransport) warmUpCalls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.warmUpCount
}

func (t *warmUpTestTransport) openCalls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.openCount
}

func (t *warmUpTestTransport) warmUpDeadlineOf() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.warmUpDeadline
}

var _ transport.Transport = (*warmUpTestTransport)(nil)

// TestWarmUp_WarmsTransport 验证预热恰好把工作交给 transport 一次：
// 调度层只用截止时间约束探测并将其委托出去，由传输层预热自己的连接池。
func TestWarmUp_WarmsTransport(t *testing.T) {
	tr := &warmUpTestTransport{}

	if err := warmUpTransport(tr, 2*time.Second); err != nil {
		t.Fatalf("unexpected error from a confirmed warm-up: %v", err)
	}

	if got := tr.warmUpCalls(); got != 1 {
		t.Errorf("expected exactly 1 transport WarmUp, got %d", got)
	}
	if got := tr.openCalls(); got != 0 {
		t.Errorf("expected no transport Open, got %d", got)
	}
}

// TestWarmUp_NilTransportIsNotAFailure 覆盖"socks_port = 0 时核心没有可预热的
// 传输层"这一形态：跳过预热绝不能表现为错误。
func TestWarmUp_NilTransportIsNotAFailure(t *testing.T) {
	if err := warmUpTransport(nil, 2*time.Second); err != nil {
		t.Errorf("expected nil for a nil transport, got %v", err)
	}
}

// TestWarmUp_ErrorIsReturned 验证尽力而为的契约：失败在此记录日志并交还给调用方
// （调用方可能忽略它），但这一层绝不会替换或丢弃该错误。
func TestWarmUp_ErrorIsReturned(t *testing.T) {
	tr := &warmUpTestTransport{warmUpErr: errors.New("probe failed")}

	err := warmUpTransport(tr, 2*time.Second)

	if err == nil {
		t.Fatal("expected the transport warm-up error to be returned, got nil")
	}
	if !strings.Contains(err.Error(), "probe failed") {
		t.Errorf("expected the transport error to be preserved, got %v", err)
	}
	if got := tr.warmUpCalls(); got != 1 {
		t.Errorf("expected 1 transport WarmUp attempt, got %d", got)
	}
}

// TestWarmUp_DefaultTimeoutWhenZero 验证回退逻辑：零（或负）超时绝不能变成一个
// 已过期的上下文，探测应改用 config.WarmUpTimeout 作为上限。
func TestWarmUp_DefaultTimeoutWhenZero(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		tr := &warmUpTestTransport{}

		start := time.Now()
		err := warmUpTransport(tr, timeout)
		if err != nil {
			t.Fatalf("timeout=%v: unexpected error from a confirmed warm-up: %v", timeout, err)
		}
		if got := tr.warmUpCalls(); got != 1 {
			t.Errorf("timeout=%v: expected 1 transport WarmUp, got %d", timeout, got)
			continue
		}

		deadline := tr.warmUpDeadlineOf()
		if deadline.IsZero() {
			t.Errorf("timeout=%v: probe context carried no deadline", timeout)
			continue
		}
		remaining := deadline.Sub(start)
		if remaining <= 0 {
			t.Errorf("timeout=%v: probe deadline already expired", timeout)
			continue
		}
		// 回退截止时间是在 warmUpTransport 内部设置的，比 start 稍晚一些，因此
		// 探测观察到它时可能略高于默认值。可以容忍这一调度开销，但仅此而已：
		// 断言的要点是零超时不会回退成无上限的东西。
		if limit := sharedconfig.WarmUpTimeout + 100*time.Millisecond; remaining > limit {
			t.Errorf("timeout=%v: probe deadline %v exceeds the default %v", timeout, remaining, sharedconfig.WarmUpTimeout)
		}
	}
}
