package proxy

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/transport"
	"golang.org/x/sync/singleflight"
)

// newTestSocksServer 构建一个接入 mock transport 的 Socks5Server，
// 这样无需任何真实网络即可测试 WarmUp。
func newTestSocksServer(tr transport.Transport) *Socks5Server {
	s := &Socks5Server{
		handler:        newTestStreamHandler(tr),
		method:         protocol.MethodAES256GCM,
		udpExch:        make(map[string]*UDPExchange),
		quit:           make(chan struct{}),
		dnsRespTimeout: 0,
	}
	s.udpExchangeSF = singleflight.Group{}
	s.directUDPSF = singleflight.Group{}
	return s
}

// TestWarmUp_WarmsTransport 验证 WarmUp 恰好把工作交给 transport 一次：
// 代理层只用截止时间约束探测并将其委托出去，由 transport 预热自己的连接池。
func TestWarmUp_WarmsTransport(t *testing.T) {
	tr := &mockTransport{}
	s := newTestSocksServer(tr)

	if err := s.WarmUp(2 * time.Second); err != nil {
		t.Fatalf("unexpected error from a confirmed warm-up: %v", err)
	}

	if got := tr.warmUpCalls(); got != 1 {
		t.Errorf("expected exactly 1 transport WarmUp, got %d", got)
	}
	if got := tr.openCalls(); got != 0 {
		t.Errorf("expected no transport Open, got %d", got)
	}
	if len(s.udpExch) != 0 {
		t.Errorf("expected exchange map to be empty after warm-up, got %d entries", len(s.udpExch))
	}
}

func TestWarmUp_NoopWhenClosing(t *testing.T) {
	tr := &mockTransport{}
	s := newTestSocksServer(tr)
	s.closing.Store(true)

	// 跳过的预热不是失败：关闭中返回 nil，绝不返回错误。
	if err := s.WarmUp(2 * time.Second); err != nil {
		t.Errorf("expected nil when server is closing, got %v", err)
	}

	if got := tr.warmUpCalls(); got != 0 {
		t.Errorf("expected no transport WarmUp when server is closing, got %d", got)
	}
}

// TestWarmUp_NilServerIsNotAFailure 覆盖 socks_port = 0 的形态：没有需要预热的
// 代理服务器，这绝不能表现为错误。
func TestWarmUp_NilServerIsNotAFailure(t *testing.T) {
	var s *Socks5Server

	if err := s.WarmUp(2 * time.Second); err != nil {
		t.Errorf("expected nil for a nil server, got %v", err)
	}
}

// TestWarmUp_ErrorIsReturned 验证尽力而为的契约：失败在此记录日志并交还给调用方
// （调用方可能忽略它），但代理层绝不会替换或丢弃该错误。
func TestWarmUp_ErrorIsReturned(t *testing.T) {
	tr := &mockTransport{warmUpErr: errors.New("probe failed")}
	s := newTestSocksServer(tr)

	err := s.WarmUp(2 * time.Second)

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

// TestWarmUp_DefaultTimeoutWhenZero 验证回退逻辑：零（或负）超时绝不能变成
// 一个已过期的上下文，探测应改用 config.WarmUpTimeout 作为上限。
func TestWarmUp_DefaultTimeoutWhenZero(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		tr := &mockTransport{}
		s := newTestSocksServer(tr)

		start := time.Now()
		err := s.WarmUp(timeout)
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
		// 回退截止时间是在 WarmUp 内部设置的，比 start 稍晚一些，因此探测观察到它时
		// 可能略高于默认值。可以容忍这一调度开销，但仅此而已：断言的要点是零超时
		// 不会回退成无上限的东西。
		if limit := config.WarmUpTimeout + 100*time.Millisecond; remaining > limit {
			t.Errorf("timeout=%v: probe deadline %v exceeds the default %v", timeout, remaining, config.WarmUpTimeout)
		}
	}
}
