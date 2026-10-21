package proxy

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
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

// awaitableStream 实现 ResponseAwaiter/ConnLiveness/ConnInvalidator 三个可选接口，
// 用来驱动引导状态机：判死重试、判活后继续等、以及"失效连接先于关闭流"的顺序。
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

// alwaysDeadline 模拟窗口到点且连接不可往返：AwaitResponse 直接报告超时。
func alwaysDeadline(context.Context) error { return context.DeadlineExceeded }

// TestOpenAndBootstrap_DeadlineRetriesOnFreshConnection 验证判死重试：窗口到点且无法
// 判活时，失效并关闭本流所在连接、丢弃其余空闲连接，再在新连接上重试。
func TestOpenAndBootstrap_DeadlineRetriesOnFreshConnection(t *testing.T) {
	first := &awaitableStream{await: alwaysDeadline}
	second := &awaitableStream{}
	tr := &mockTransport{streams: []transport.Stream{first, second}}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
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

// TestOpenAndBootstrap_LateResponseKeepsAliveConnection 验证判活的用途：探测确认同
// 连接可往返（服务端只是还在解析目标域名）时不重试、不关连接——"慢"与"死"的分界。
func TestOpenAndBootstrap_LateResponseKeepsAliveConnection(t *testing.T) {
	first := &awaitableStream{await: alwaysDeadline, alive: true, aliveKnown: true}
	tr := &mockTransport{streams: []transport.Stream{first}}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
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

// TestOpenAndBootstrap_TransportErrorRetriesImmediately 验证传输层错误立即换连接重试，
// 不等满窗口，也不做判活探测。
func TestOpenAndBootstrap_TransportErrorRetriesImmediately(t *testing.T) {
	first := &awaitableStream{await: func(context.Context) error { return errors.New("connection reset by peer") }}
	second := &awaitableStream{}
	tr := &mockTransport{streams: []transport.Stream{first, second}}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
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

// TestOpenAndBootstrap_ExhaustedAttemptsReportError 验证次数耗尽后把最后一次失败交给
// 应用，且每次放弃都丢弃其余空闲连接——否则后续请求会逐个再踩一遍旧网络的死连接。
func TestOpenAndBootstrap_ExhaustedAttemptsReportError(t *testing.T) {
	streams := make([]transport.Stream, 0, bootstrapMaxAttempts)
	for range bootstrapMaxAttempts {
		streams = append(streams, &awaitableStream{await: alwaysDeadline})
	}
	tr := &mockTransport{streams: streams}
	h := newTestStreamHandler(tr)

	_, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
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

// TestOpenAndBootstrap_ContextCanceledNoRetry 验证上层取消（核心停止、本地连接已断）
// 时立即上报 ctx 错误，不重试也不丢弃连接池。
func TestOpenAndBootstrap_ContextCanceledNoRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	first := &awaitableStream{await: func(context.Context) error {
		cancel()
		return context.Canceled
	}}
	tr := &mockTransport{streams: []transport.Stream{first}}
	h := newTestStreamHandler(tr)

	_, err := h.openAndBootstrap(ctx, testTCPRequest("example.com:443"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if tr.openCalls() != 1 {
		t.Errorf("expected 1 Open call (no retry after cancellation), got %d", tr.openCalls())
	}
	if tr.closeIdleCalls() != 0 {
		t.Errorf("expected no CloseIdle call after cancellation, got %d", tr.closeIdleCalls())
	}
	// 取消不是判死：只关本流，绝不失效连接——它健康且被同槽位的在飞流共享。
	if _, _, invalidates, closes := first.counters(); invalidates != 0 || closes != 1 {
		t.Errorf("first stream: invalidates=%d closes=%d, want 0/1", invalidates, closes)
	}
}

// TestOpenAndBootstrap_ResponseReadyNoRetry 验证"响应已就绪"（含服务端拒绝）不触发
// 重试或连接失效，分类交给首次 Read。
func TestOpenAndBootstrap_ResponseReadyNoRetry(t *testing.T) {
	first := &awaitableStream{await: func(context.Context) error { return nil }}
	tr := &mockTransport{streams: []transport.Stream{first}}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
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

// TestOpenAndBootstrap_SettlesBeforeDroppingIdleConnections 验证判死路径的顺序：
// 失效连接 → 关闭流 → 等本流 RoundTrip 收敛 → CloseIdle()。CloseIdle 提前会漏掉这条
// 仍被在飞流占用的连接，重试的 Open 再次拿到它，白费一次尝试。
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

	bs, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
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

// TestOpenAndBootstrap_ResponseWindowIsBounded 验证引导窗口真的作用到 AwaitResponse：
// 在窗口到点前不会自己返回的流，最终仍由该窗口打断。
func TestOpenAndBootstrap_ResponseWindowIsBounded(t *testing.T) {
	const window = 20 * time.Millisecond
	old := bootstrapResponseTimeout
	bootstrapResponseTimeout = window
	t.Cleanup(func() { bootstrapResponseTimeout = old })

	// 第一次 AwaitResponse 是引导等待窗口，后续是判死后的 settle，只记第一次耗时。
	windowEnded := make(chan time.Duration, 1)
	var recordOnce sync.Once
	await := func(ctx context.Context) error {
		<-ctx.Done()

		// 窗口起点必须由 deadline 反推：窗口在 awaitBootstrapResponse 的
		// context.WithTimeout 处创建，与这里的接口调用之间还有开销，从调用内部起算
		// 量出的值恒小于窗口；Windows 上该开销被调度放大到毫秒级，断言会偶发失败。
		deadline, ok := ctx.Deadline()
		if !ok {
			// 没有 deadline 就无从衡量窗口：直接失败，别让 <-ctx.Done() 挂起成测试超时。
			return errors.New("AwaitResponse was called without the bootstrap window")
		}
		recordOnce.Do(func() { windowEnded <- time.Since(deadline.Add(-window)) })
		return ctx.Err()
	}
	streams := make([]transport.Stream, 0, bootstrapMaxAttempts)
	for range bootstrapMaxAttempts {
		streams = append(streams, &awaitableStream{await: await})
	}
	tr := &mockTransport{streams: streams}
	h := newTestStreamHandler(tr)

	_, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}
	select {
	case elapsed := <-windowEnded:
		if elapsed < window {
			t.Errorf("AwaitResponse returned after %v, want >= the %v window", elapsed, window)
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
	// onCloseIdle 在计数递增后回调，供用例断言判死路径的动作顺序。
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
	return NewStreamHandler(tr, key, shaper.Config{}, sharedconfig.Timeouts{})
}

func testTCPRequest(target string) streamRequest {
	return tcpStreamRequest(target, protocol.MethodAES256GCM)
}

func TestOpenAndBootstrap_SuccessFirstTry(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{},
		},
	}
	h := newTestStreamHandler(tr)

	bs, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
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

	bs, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
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

	_, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
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

	_, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
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

	_, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
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

// saltCapturingTransport 包装 Transport 并记录每次 Open 的 Salt。
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

func (t *saltCapturingTransport) CloseIdle()                      {}
func (t *saltCapturingTransport) Stats() transport.TransportStats { return transport.TransportStats{} }
func (t *saltCapturingTransport) Close() error                    { return t.inner.Close() }

// TestOpenAndBootstrap_FreshSaltPerAttempt 验证每次尝试都重新生成 salt，服务端的重放
// 保护因此不会把重试当成重放。
func TestOpenAndBootstrap_FreshSaltPerAttempt(t *testing.T) {
	tr := &mockTransport{
		streams: []transport.Stream{
			&mockStream{writeErr: io.ErrClosedPipe},
			&mockStream{},
		},
	}
	wrapped := &saltCapturingTransport{inner: tr}
	h := newTestStreamHandler(wrapped)

	bs, err := h.openAndBootstrap(context.Background(), testTCPRequest("example.com:443"))
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

// TestBootstrapRecordFitsWriteLimit 固定"手工拼装的引导记录一定能被加密层接受"：引导
// 记录是唯一不走整形器的明文写入路径，没有单帧校验也没有预冲刷边界，合并判据与填充
// 预算必须与 WriteRecord 的上限自洽，否则大包会在 UDP 交换中途被拒。断言直接对着真实
// writer，并固定超限的额外帧由拼装函数自己拒绝。
func TestBootstrapRecordFitsWriteLimit(t *testing.T) {
	const target = "example.com:443"
	const method = protocol.MethodAES256GCM
	datagram := func(size int) []protocol.Frame {
		return []protocol.Frame{protocol.NewFrameDATAGRAM(make([]byte, size))}
	}
	build := func(extra []protocol.Frame) ([]byte, error) {
		t.Helper()
		return buildBootstrapPlaintext(udpStreamRequest(target, method).withFrames(extra...))
	}
	write := func(plaintext []byte) error {
		t.Helper()
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1)
		}
		sk, err := crypto.NewStreamKeys(key, []byte("1234567890123456"), "/v3/udp")
		if err != nil {
			t.Fatalf("stream keys: %v", err)
		}
		w, err := sk.BootstrapWriter(io.Discard)
		if err != nil {
			t.Fatalf("bootstrap writer: %v", err)
		}
		return w.WriteRecord(plaintext)
	}

	maxPayload := bootstrapMaxPayload(target)
	for _, size := range []int{0, 1, 1400, maxPayload - 1, maxPayload} {
		plaintext, err := build(datagram(size))
		if err != nil {
			t.Fatalf("payload=%d: 判据说可以合并，拼装却拒绝了：%v", size, err)
		}
		if len(plaintext) > protocol.MaxWriteRecordPlaintext {
			t.Fatalf("payload=%d: 明文 %d 超过写入上限 %d",
				size, len(plaintext), protocol.MaxWriteRecordPlaintext)
		}
		if err := write(plaintext); err != nil {
			t.Fatalf("payload=%d: 判据说可以合并，加密层却拒绝了：%v", size, err)
		}
	}

	// 判据边界正好贴着写入上限：再多 1 字节连填充也放不下，拼装函数必须自己拒绝。
	if _, err := build(datagram(maxPayload + 1)); err == nil {
		t.Fatal("超出判据的载荷必须被拼装函数拒绝")
	}
	// 同一个越界长度也要确认加密层确实不收：三者夹的是同一条线。
	over := protocol.EncodeFrames([]protocol.Frame{
		protocol.NewFrameHANDSHAKE(protocol.Handshake{
			Version: protocol.Version3,
			Proto:   protocol.ProtoUDP,
			Method:  method,
			Target:  target,
		}),
		protocol.NewFrameDATAGRAM(make([]byte, maxPayload+1)),
	})
	if err := write(over); err == nil {
		t.Fatal("超出判据的载荷本应无法写入引导记录")
	}

	// 填充长度随机（1~63 字节），距上限 60 字节的载荷约有四成次数会被顶过上限，
	// 故重复 200 次才抓得住。余量从判据反推而非写死，上限调整后仍压在同一个位置。
	nearLimit := maxPayload - 60
	for i := range 200 {
		plaintext, err := build(datagram(nearLimit))
		if err != nil {
			t.Fatalf("第 %d 次：%v", i, err)
		}
		if len(plaintext) > protocol.MaxWriteRecordPlaintext {
			t.Fatalf("第 %d 次：填充把明文顶到 %d，超过上限 %d",
				i, len(plaintext), protocol.MaxWriteRecordPlaintext)
		}
		if err := write(plaintext); err != nil {
			t.Fatalf("第 %d 次：%v", i, err)
		}
	}
}
