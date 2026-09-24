package proxy

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/transport"
)

type mockStream struct {
	writeErr error
	written  []byte
}

func (s *mockStream) Read(p []byte) (int, error) { return 0, io.EOF }
func (s *mockStream) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	s.written = append(s.written, p...)
	return len(p), nil
}
func (s *mockStream) CloseWrite() error { return nil }
func (s *mockStream) Close() error      { return nil }

// awaitableStream 是实现了三个可选引导接口的测试流（transport.ResponseAwaiter/
// ConnLiveness/ConnInvalidator），用来验证代理层的引导状态机：判死重试、判活后
// 继续等待，以及调用顺序（失效连接必须先于关闭流）。
type awaitableStream struct {
	mockStream

	await      func(ctx context.Context) error
	alive      bool
	aliveKnown bool

	mu          sync.Mutex
	awaitCalls  int
	aliveCalls  int
	invalidates int
	closes      int
}

func (s *awaitableStream) AwaitResponse(ctx context.Context) error {
	s.mu.Lock()
	s.awaitCalls++
	await := s.await
	s.mu.Unlock()
	if await == nil {
		return nil
	}
	return await(ctx)
}

func (s *awaitableStream) ConnAlive(context.Context) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.aliveCalls++
	return s.alive, s.aliveKnown
}

func (s *awaitableStream) InvalidateConn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidates++
}

func (s *awaitableStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closes++
	return nil
}

func (s *awaitableStream) counters() (await, alive, invalidates, closes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.awaitCalls, s.aliveCalls, s.invalidates, s.closes
}

var (
	_ transport.Stream          = (*awaitableStream)(nil)
	_ transport.ResponseAwaiter = (*awaitableStream)(nil)
	_ transport.ConnLiveness    = (*awaitableStream)(nil)
	_ transport.ConnInvalidator = (*awaitableStream)(nil)
)

// alwaysDeadline 模拟"窗口到点且连接不可往返"：AwaitResponse 直接报告窗口超时，
// 判活返回"无法判定"。
func alwaysDeadline(context.Context) error { return context.DeadlineExceeded }

// TestOpenAndBootstrap_DeadlineRetriesOnFreshConnection 验证引导阶段的判死重试：
// 等待窗口到点且判活无法确认时，失效并关闭本流所在的连接、丢弃其余空闲连接，
// 然后在新的连接上重试，应用侧只看到一次成功的引导。
func TestOpenAndBootstrap_DeadlineRetriesOnFreshConnection(t *testing.T) {
	first := &awaitableStream{await: alwaysDeadline}
	second := &awaitableStream{}
	tr := &mockTransport{streams: []transport.Stream{first, second}}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	defer bs.stream.Close() //nolint:errcheck

	if tr.openCalls() != 2 {
		t.Errorf("expected 2 Open calls, got %d", tr.openCalls())
	}
	if _, alive, invalidates, closes := first.counters(); invalidates != 1 || closes != 1 || alive != 1 {
		t.Errorf("first stream: invalidates=%d closes=%d alive=%d, want 1/1/1 (probed then judged dead)", invalidates, closes, alive)
	}
	if tr.closeIdleCalls() != 1 {
		t.Errorf("expected 1 CloseIdle call after judging the connection dead, got %d", tr.closeIdleCalls())
	}
}

// TestOpenAndBootstrap_LateResponseKeepsAliveConnection 验证判活的用途：等待窗口
// 到点但同连接探测确认可往返（服务端只是还在解析目标域名）时不重试、不关连接，
// 交回中继继续等——这正是"慢"与"死"的分界。
func TestOpenAndBootstrap_LateResponseKeepsAliveConnection(t *testing.T) {
	first := &awaitableStream{await: alwaysDeadline, alive: true, aliveKnown: true}
	tr := &mockTransport{streams: []transport.Stream{first}}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err != nil {
		t.Fatalf("expected the alive connection to be kept, got: %v", err)
	}
	defer bs.stream.Close() //nolint:errcheck

	if tr.openCalls() != 1 {
		t.Errorf("expected 1 Open call (no retry for an alive connection), got %d", tr.openCalls())
	}
	if _, alive, invalidates, closes := first.counters(); alive != 1 || invalidates != 0 || closes != 0 {
		t.Errorf("first stream: alive=%d invalidates=%d closes=%d, want 1/0/0", alive, invalidates, closes)
	}
	if tr.closeIdleCalls() != 0 {
		t.Errorf("expected no CloseIdle call, got %d", tr.closeIdleCalls())
	}
}

// TestOpenAndBootstrap_TransportErrorRetriesImmediately 验证传输层错误（连接在
// 写入/响应阶段就坏了）立即换连接重试，不必等满窗口，也不做判活探测。
func TestOpenAndBootstrap_TransportErrorRetriesImmediately(t *testing.T) {
	first := &awaitableStream{await: func(context.Context) error { return errors.New("connection reset by peer") }}
	second := &awaitableStream{}
	tr := &mockTransport{streams: []transport.Stream{first, second}}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	defer bs.stream.Close() //nolint:errcheck

	if tr.openCalls() != 2 {
		t.Errorf("expected 2 Open calls, got %d", tr.openCalls())
	}
	if _, alive, _, _ := first.counters(); alive != 0 {
		t.Errorf("liveness must not be probed on a transport error, got %d calls", alive)
	}
}

// TestOpenAndBootstrap_ExhaustedAttemptsReportError 验证尝试次数耗尽后把最后一次
// 的失败交给应用，并且每次放弃都丢弃了其余空闲连接（否则后续请求会逐个再踩一遍
// 旧网络上的死连接）。
func TestOpenAndBootstrap_ExhaustedAttemptsReportError(t *testing.T) {
	streams := make([]transport.Stream, 0, bootstrapMaxAttempts)
	for range bootstrapMaxAttempts {
		streams = append(streams, &awaitableStream{await: alwaysDeadline})
	}
	tr := &mockTransport{streams: streams}
	h := newTestStreamHandler(tr)

	_, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err == nil {
		t.Fatal("expected an error after exhausting attempts, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected the error to wrap context.DeadlineExceeded, got: %v", err)
	}
	if tr.openCalls() != bootstrapMaxAttempts {
		t.Errorf("expected %d Open calls, got %d", bootstrapMaxAttempts, tr.openCalls())
	}
	if got, want := tr.closeIdleCalls(), bootstrapMaxAttempts-1; got != want {
		t.Errorf("CloseIdle calls = %d, want %d (one per retry)", got, want)
	}
}

// TestOpenAndBootstrap_ContextCanceledNoRetry 验证上层取消（核心停止、本地连接
// 已断）时立即上报 ctx 错误，不做重试，也不丢弃连接池。
func TestOpenAndBootstrap_ContextCanceledNoRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	first := &awaitableStream{await: func(context.Context) error {
		cancel()
		return context.Canceled
	}}
	tr := &mockTransport{streams: []transport.Stream{first}}
	h := newTestStreamHandler(tr)

	_, err := h.openAndBootstrap(ctx, "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if tr.openCalls() != 1 {
		t.Errorf("expected 1 Open call (no retry after cancellation), got %d", tr.openCalls())
	}
	if tr.closeIdleCalls() != 0 {
		t.Errorf("expected no CloseIdle call after cancellation, got %d", tr.closeIdleCalls())
	}
	// 取消不是判死：只关闭本流，绝不能失效连接——这条连接是健康的，且被同槽位
	// 其他在飞流共享，关掉它会连带中断它们。
	if _, _, invalidates, closes := first.counters(); invalidates != 0 || closes != 1 {
		t.Errorf("first stream: invalidates=%d closes=%d, want 0/1", invalidates, closes)
	}
}

// TestOpenAndBootstrap_ResponseReadyNoRetry 验证"响应已就绪"（含服务端拒绝）不
// 触发任何重试或连接失效：分类交给首次 Read。
func TestOpenAndBootstrap_ResponseReadyNoRetry(t *testing.T) {
	first := &awaitableStream{await: func(context.Context) error { return nil }}
	tr := &mockTransport{streams: []transport.Stream{first}}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer bs.stream.Close() //nolint:errcheck

	if tr.openCalls() != 1 {
		t.Errorf("expected 1 Open call, got %d", tr.openCalls())
	}
	if _, _, invalidates, _ := first.counters(); invalidates != 0 {
		t.Errorf("a ready response must not invalidate the connection, got %d", invalidates)
	}
}

// TestOpenAndBootstrap_SettlesBeforeDroppingIdleConnections 验证判死路径的动作
// 顺序：失效连接 → 关闭流 → 等本流 RoundTrip 收敛 → CloseIdle()。顺序反了
// （尤其是 CloseIdle 提前）会让 CloseIdleConnections 漏掉这条仍被在飞流占用的
// 连接，重试的 Open 会再次拿到它，白费一次尝试。
func TestOpenAndBootstrap_SettlesBeforeDroppingIdleConnections(t *testing.T) {
	settledAfterClose := false
	first := &awaitableStream{}
	first.await = func(context.Context) error {
		if _, _, _, closes := first.counters(); closes == 1 {
			settledAfterClose = true
		}
		return context.DeadlineExceeded
	}
	second := &awaitableStream{}
	tr := &mockTransport{streams: []transport.Stream{first, second}}
	tr.onCloseIdle = func() {
		if await, _, _, _ := first.counters(); await < 2 {
			t.Error("CloseIdle must run after the dead stream settled")
		}
	}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	defer bs.stream.Close() //nolint:errcheck

	if !settledAfterClose {
		t.Error("the dead stream must be closed before the settle wait")
	}
	if _, _, invalidates, closes := first.counters(); invalidates != 1 || closes != 1 {
		t.Errorf("first stream: invalidates=%d closes=%d, want 1/1", invalidates, closes)
	}
}

// TestOpenAndBootstrap_ResponseWindowIsBounded 验证等待窗口真的被应用于
// AwaitResponse：一个在窗口到点前不会自己返回的流，最终仍由引导窗口打断。
func TestOpenAndBootstrap_ResponseWindowIsBounded(t *testing.T) {
	old := bootstrapResponseTimeout
	bootstrapResponseTimeout = 20 * time.Millisecond
	t.Cleanup(func() { bootstrapResponseTimeout = old })

	// 第一次 AwaitResponse 是引导等待窗口；后续调用是判死后的 settle 等待，
	// 只记录第一次的耗时。
	windowEnded := make(chan time.Duration, 1)
	var recordOnce sync.Once
	await := func(ctx context.Context) error {
		start := time.Now()
		<-ctx.Done()
		recordOnce.Do(func() { windowEnded <- time.Since(start) })
		return ctx.Err()
	}
	streams := make([]transport.Stream, 0, bootstrapMaxAttempts)
	for range bootstrapMaxAttempts {
		streams = append(streams, &awaitableStream{await: await})
	}
	tr := &mockTransport{streams: streams}
	h := newTestStreamHandler(tr)

	_, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
	select {
	case elapsed := <-windowEnded:
		if elapsed < bootstrapResponseTimeout {
			t.Errorf("AwaitResponse returned after %v, want >= the %v window", elapsed, bootstrapResponseTimeout)
		}
	case <-time.After(time.Second):
		t.Fatal("AwaitResponse was never interrupted by the bootstrap window")
	}
}

type mockTransport struct {
	mu             sync.Mutex
	openCount      int
	closeIdleCount int
	streams        []transport.Stream
	openErrs       []error
	// onCloseIdle 在 CloseIdle 递增计数后被调用，供用例断言判死路径的动作顺序。
	onCloseIdle func()
}

func (m *mockTransport) Open(ctx context.Context, req transport.OpenRequest) (transport.Stream, error) {
	m.mu.Lock()
	idx := m.openCount
	m.openCount++
	m.mu.Unlock()

	if idx < len(m.openErrs) && m.openErrs[idx] != nil {
		return nil, m.openErrs[idx]
	}
	if idx < len(m.streams) {
		return m.streams[idx], nil
	}
	return &mockStream{}, nil
}

// WarmUp 是 transport.Transport 的接口要求：预热的实现与断言在 runner 侧
// （见 runner/warmup_test.go），代理层不再调用它。
func (m *mockTransport) WarmUp(context.Context) error { return nil }

func (m *mockTransport) CloseIdle() {
	m.mu.Lock()
	m.closeIdleCount++
	hook := m.onCloseIdle
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
}

func (m *mockTransport) Stats() transport.TransportStats { return transport.TransportStats{} }
func (m *mockTransport) Close() error                    { return nil }

func (m *mockTransport) openCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.openCount
}

func (m *mockTransport) closeIdleCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closeIdleCount
}

func newTestStreamHandler(tr transport.Transport) *StreamHandler {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return NewStreamHandler(tr, key, shaper.Config{}, 0)
}

func TestOpenAndBootstrap_SuccessFirstTry(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{},
		},
	}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bs == nil {
		t.Fatal("expected non-nil bootstrapSession")
	}
	if tr.openCalls() != 1 {
		t.Errorf("expected 1 Open call, got %d", tr.openCalls())
	}
	defer bs.stream.Close() //nolint:errcheck
}

func TestOpenAndBootstrap_RetryOnErrClosedPipe(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{writeErr: io.ErrClosedPipe},
			&mockStream{},
		},
	}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if bs == nil {
		t.Fatal("expected non-nil bootstrapSession")
	}
	if tr.openCalls() != 2 {
		t.Errorf("expected 2 Open calls, got %d", tr.openCalls())
	}
	defer bs.stream.Close() //nolint:errcheck
}

func TestOpenAndBootstrap_NoRetryOnNonClosedPipeErr(t *testing.T) {
	otherErr := errors.New("some write error")
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{writeErr: otherErr},
		},
	}
	h := newTestStreamHandler(tr)

	_, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, otherErr) {
		t.Errorf("expected error to wrap otherErr, got: %v", err)
	}
	if tr.openCalls() != 1 {
		t.Errorf("expected 1 Open call (no retry), got %d", tr.openCalls())
	}
}

func TestOpenAndBootstrap_AllRetriesFail(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{writeErr: io.ErrClosedPipe},
			&mockStream{writeErr: io.ErrClosedPipe},
			&mockStream{writeErr: io.ErrClosedPipe},
		},
	}
	h := newTestStreamHandler(tr)

	_, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("expected error to wrap io.ErrClosedPipe, got: %v", err)
	}
	if tr.openCalls() != bootstrapMaxAttempts {
		t.Errorf("expected %d Open calls (max attempts), got %d", bootstrapMaxAttempts, tr.openCalls())
	}
}

func TestOpenAndBootstrap_OpenFailureNoRetry(t *testing.T) {
	openErr := errors.New("transport unavailable")
	tr := &mockTransport{
		openErrs: []error{openErr},
	}
	h := newTestStreamHandler(tr)

	_, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, openErr) {
		t.Errorf("expected error to wrap openErr, got: %v", err)
	}
	if tr.openCalls() != 1 {
		t.Errorf("expected 1 Open call, got %d", tr.openCalls())
	}
}

// saltCapturingTransport 包装一个 Transport，并记录每次 Open 调用中的 Salt。
type saltCapturingTransport struct {
	inner transport.Transport
	mu    sync.Mutex
	salts []string
}

func (t *saltCapturingTransport) Open(ctx context.Context, req transport.OpenRequest) (transport.Stream, error) {
	t.mu.Lock()
	t.salts = append(t.salts, req.Salt)
	t.mu.Unlock()
	return t.inner.Open(ctx, req)
}

func (t *saltCapturingTransport) WarmUp(ctx context.Context) error { return t.inner.WarmUp(ctx) }
func (t *saltCapturingTransport) CloseIdle()                       {}
func (t *saltCapturingTransport) Stats() transport.TransportStats  { return transport.TransportStats{} }
func (t *saltCapturingTransport) Close() error                     { return t.inner.Close() }

func TestOpenAndBootstrap_FreshSaltPerAttempt(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{writeErr: io.ErrClosedPipe},
			&mockStream{},
		},
	}
	wrapped := &saltCapturingTransport{inner: tr}
	h := newTestStreamHandler(wrapped)

	bs, err := h.openAndBootstrap(context.Background(), "/v3/tcp", protocol.ProtoTCP, "example.com:443", protocol.MethodAES256GCM, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer bs.stream.Close() //nolint:errcheck

	wrapped.mu.Lock()
	defer wrapped.mu.Unlock()
	if len(wrapped.salts) != 2 {
		t.Fatalf("expected 2 salts, got %d", len(wrapped.salts))
	}
	if wrapped.salts[0] == "" || wrapped.salts[1] == "" {
		t.Error("expected non-empty salts")
	}
	if wrapped.salts[0] == wrapped.salts[1] {
		t.Error("expected different salts for each retry attempt")
	}
}
