package http2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/transport"
)

// newRecoveryStream 构造一条用于引导恢复测试的流：结果落定前
// Read/AwaitResponse 会等待，Close 可以由用例触发。
func newRecoveryStream(t *testing.T) *http2Stream {
	t.Helper()
	s, pr := newTestStream()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = s.Close()
	})
	return s
}

// TestHTTP2Stream_AwaitResponse 覆盖 transport.ResponseAwaiter 的四种结果，
// 关键是"服务端拒绝"必须被视为结果已就绪，而不是网络故障。
func TestHTTP2Stream_AwaitResponse(t *testing.T) {
	t.Run("response ready", func(t *testing.T) {
		s := newRecoveryStream(t)
		s.deliver(roundTripResult{
			resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))},
		})
		if err := s.AwaitResponse(context.Background()); err != nil {
			t.Fatalf("AwaitResponse = %v, want nil for a ready response", err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		s := newRecoveryStream(t)
		sentinel := errors.New("connection reset by peer")
		s.deliver(roundTripResult{err: sentinel})
		err := s.AwaitResponse(context.Background())
		if !errors.Is(err, sentinel) {
			t.Fatalf("AwaitResponse = %v, want it to wrap the transport error", err)
		}
	})

	t.Run("handshake rejection is a ready result", func(t *testing.T) {
		s := newRecoveryStream(t)
		s.deliver(roundTripResult{err: &transport.HandshakeRejectedError{
			StatusCode: http.StatusBadRequest,
			Status:     "400 Bad Request",
		}})
		if err := s.AwaitResponse(context.Background()); err != nil {
			t.Fatalf("AwaitResponse = %v, want nil for a rejected handshake (not a network failure)", err)
		}
	})

	t.Run("ctx expiry", func(t *testing.T) {
		s := newRecoveryStream(t)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		if err := s.AwaitResponse(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("AwaitResponse = %v, want context.DeadlineExceeded", err)
		}
	})
}

// TestHTTP2Stream_ConnAlive 验证判活语义："拿到任何响应"即活，只有不可往返才判死；
// 未配置探测令牌时报告"无法判定"。
func TestHTTP2Stream_ConnAlive(t *testing.T) {
	t.Run("probe payload counts as alive", func(t *testing.T) {
		ts, token := newProbeServer(t)
		prober := &slotProber{serverURL: ts.URL, token: token, payloadSize: testProbePayloadSize}
		s := livenessStream(newProbeSlot(), prober.alive)

		alive, ok := s.ConnAlive(context.Background())
		if !ok || !alive {
			t.Fatalf("ConnAlive = (%v, %v), want (true, true)", alive, ok)
		}
	})

	t.Run("rate limited response counts as alive", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
		}))
		t.Cleanup(ts.Close)
		prober := &slotProber{serverURL: ts.URL, token: "unused", payloadSize: testProbePayloadSize}
		s := livenessStream(newProbeSlot(), prober.alive)

		alive, ok := s.ConnAlive(context.Background())
		if !ok || !alive {
			t.Fatalf("ConnAlive = (%v, %v), want (true, true) for a 429", alive, ok)
		}
	})

	t.Run("fallback page counts as alive", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><body>fallback</body></html>"))
		}))
		t.Cleanup(ts.Close)
		prober := &slotProber{serverURL: ts.URL, token: "unused", payloadSize: testProbePayloadSize}
		s := livenessStream(newProbeSlot(), prober.alive)

		alive, ok := s.ConnAlive(context.Background())
		if !ok || !alive {
			t.Fatalf("ConnAlive = (%v, %v), want (true, true) for a fallback page", alive, ok)
		}
	})

	t.Run("unreachable server is dead", func(t *testing.T) {
		ts, token := newProbeServer(t)
		deadURL := ts.URL
		ts.Close()
		prober := &slotProber{serverURL: deadURL, token: token, payloadSize: testProbePayloadSize}
		s := livenessStream(newProbeSlot(), prober.alive)

		alive, ok := s.ConnAlive(context.Background())
		if !ok || alive {
			t.Fatalf("ConnAlive = (%v, %v), want (false, true) for an unreachable server", alive, ok)
		}
	})

	t.Run("timeout is dead", func(t *testing.T) {
		release := make(chan struct{})
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-release
		}))
		t.Cleanup(func() {
			close(release)
			ts.Close()
		})
		prober := &slotProber{serverURL: ts.URL, token: "unused", payloadSize: testProbePayloadSize}
		s := livenessStream(newProbeSlot(), prober.alive)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		alive, ok := s.ConnAlive(ctx)
		if !ok || alive {
			t.Fatalf("ConnAlive = (%v, %v), want (false, true) after the probe timed out", alive, ok)
		}
	})

	t.Run("no liveness function cannot judge", func(t *testing.T) {
		s := &http2Stream{slot: newProbeSlot()}
		if alive, ok := s.ConnAlive(context.Background()); ok || alive {
			t.Fatalf("ConnAlive = (%v, %v), want (false, false) without a prober", alive, ok)
		}
		empty := &http2Stream{}
		if alive, ok := empty.ConnAlive(context.Background()); ok || alive {
			t.Fatalf("ConnAlive = (%v, %v), want (false, false) without a slot", alive, ok)
		}
	})

	t.Run("stream not submitted yet cannot judge", func(t *testing.T) {
		// 探针有了，但这条流还没有提交到任何一代池上：判活探测的对象是"本流
		// 用过的那一代连接"，此时没有对象可探测，只能如实报告"无法判定"
		// （调用方按判死处理）。
		slot := newProbeSlot()
		prober := &slotProber{serverURL: "https://127.0.0.1:1", token: "unused", payloadSize: testProbePayloadSize}
		s := &http2Stream{slot: slot, liveness: prober.alive}
		if alive, ok := s.ConnAlive(context.Background()); ok || alive {
			t.Fatalf("ConnAlive = (%v, %v), want (false, false) before the request is submitted", alive, ok)
		}
	})
}

// countingConn 只用于断言底层连接被关闭了几次；其余方法由内嵌的 net.Conn 提供。
type countingConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *countingConn) Close() error {
	c.closes.Add(1)
	return nil
}

func newCountingSlot(conn net.Conn) (*transportSlot, *slotConn) {
	slot := slotWithPool(&http.Transport{})
	return slot, attachConn(slot, conn)
}

// livenessStream 构造一条已提交到槽位当前一代、带判活探针的流：ConnAlive 是
// 连接作用域的，探测对象是流自己那一代（见 http2Stream.ConnAlive）。这一代必须
// 已经有一条连接身份——"这一代没有连接就不探测"（见 slotProber.alive）由
// probe_test 单独覆盖，这里测的是探测结论本身。
func livenessStream(slot *transportSlot, liveness func(context.Context, *slotTransport) (bool, bool)) *http2Stream {
	attachConn(slot, &countingConn{})
	s := &http2Stream{slot: slot, liveness: liveness}
	if gen := slot.generation(); gen != nil {
		s.gen.Store(gen)
	}
	return s
}

// TestHTTP2Stream_InvalidateConnClosesExactlyOnce 覆盖 §4.8(a)：同一连接上的多条
// 流并发判定死亡时，底层 Close 恰好发生一次，其余调用是无操作。
func TestHTTP2Stream_InvalidateConnClosesExactlyOnce(t *testing.T) {
	conn := &countingConn{}
	slot, _ := newCountingSlot(conn)
	gen := slot.generation()

	const streams = 8
	streamsOnConn := make([]*http2Stream, 0, streams)
	for range streams {
		s := &http2Stream{slot: slot}
		s.gen.Store(gen)
		streamsOnConn = append(streamsOnConn, s)
	}

	var wg sync.WaitGroup
	for _, s := range streamsOnConn {
		wg.Go(s.InvalidateConn)
	}
	wg.Wait()

	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("underlying Close called %d times, want exactly 1", got)
	}
	if slot.connIdentity() != nil {
		t.Fatal("the generation's conn pointer must be cleared after invalidation")
	}
}

// TestHTTP2Stream_InvalidateConnDoesNotKillNewConnection 是"把新连接记成自己的
// 身份、之后误杀健康连接"这个既有窗口的回归测试（#229 之后仍然存在的问题）：
// 流只持有自己提交时的那一代，槽位换到新一代并拨出新连接之后，旧一代的判死
// 既杀不掉新连接，也不会动新一代的池。
func TestHTTP2Stream_InvalidateConnDoesNotKillNewConnection(t *testing.T) {
	stale := &countingConn{}
	healthy := &countingConn{}

	slot := slotWithGenFactory()
	oldGen := slot.generation()
	attachConn(slot, stale)
	// 另一条流（或 net/http 自己）已经让这条连接作废：旧连接被关掉，槽位换代。
	if !slot.invalidateConn(oldGen, "other stream") {
		t.Fatal("the first invalidation must win")
	}
	newGen := slot.generation()
	if newGen == oldGen {
		t.Fatal("the pool must have been replaced")
	}
	healthySC := attachConn(slot, healthy)

	// 一条仍绑在旧一代上的流，之后才被判死。
	s := &http2Stream{slot: slot}
	s.gen.Store(oldGen)
	s.InvalidateConn()

	if got := stale.closes.Load(); got != 1 {
		t.Fatalf("stale connection closed %d times, want 1 (the first invalidation only)", got)
	}
	if got := healthy.closes.Load(); got != 0 {
		t.Fatalf("the healthy connection on the new generation was closed %d times, want 0", got)
	}
	if slot.generation() != newGen {
		t.Fatal("a retired generation's identity must not replace the current pool")
	}
	if newGen.conn.Load() != healthySC {
		t.Fatal("the newer generation must keep its own connection")
	}
}

// TestHTTP2Stream_InvalidateConnWithoutGenerationIsNoOp 覆盖两条安全边界：还没
// 提交到任何一代上的流（没有身份可判）以及这一代已经没有连接（已关闭/已作废）
// 时，失效必须安全返回。
func TestHTTP2Stream_InvalidateConnWithoutGenerationIsNoOp(t *testing.T) {
	conn := &countingConn{}
	slot, sc := newCountingSlot(conn)

	s := &http2Stream{slot: slot} // gen 为 nil：请求还没提交
	s.InvalidateConn()
	if conn.closes.Load() != 0 {
		t.Fatal("no connection may be closed before the request is submitted")
	}
	if slot.connIdentity() != sc {
		t.Fatal("the connection identity must be untouched")
	}

	// 这一代没有连接（从未拨号，或已被回收）：无操作，不得换代。
	empty := slotWithGenFactory()
	emptyGen := empty.generation()
	noConn := &http2Stream{slot: empty}
	noConn.gen.Store(emptyGen)
	noConn.InvalidateConn()
	if empty.generation() != emptyGen {
		t.Fatal("invalidating a generation without a connection must not replace the pool")
	}

	noSlot := &http2Stream{}
	noSlot.InvalidateConn()
}

// TestTrackedConnCloseRetiresGeneration 固定"代 == 连接"不变量的执行点：
// net/http 自然回收连接（trackedConn.Close）之后，这一代连同它的连接身份一起
// 作废，槽位换到新一代——下一条流只能拨号，而持有旧一代的流已经读不到任何连接。
func TestTrackedConnCloseRetiresGeneration(t *testing.T) {
	conn := &countingConn{}

	slot := slotWithGenFactory()
	gen := slot.generation()
	oldPool := slot.transport()
	sc := attachConn(slot, conn)

	tracked := &trackedConn{Conn: conn, gen: gen, self: sc}
	if err := tracked.Close(); err != nil {
		t.Fatalf("trackedConn.Close: %v", err)
	}

	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("connection closed %d times, want 1", got)
	}
	if gen.conn.Load() != nil {
		t.Fatal("the retired generation must not keep a connection identity")
	}
	if slot.generation() == gen {
		t.Fatal("closing the connection must advance the generation")
	}
	if slot.connIdentity() != nil {
		t.Fatal("the new generation must start without a connection")
	}
	if slot.transport() == oldPool {
		t.Fatal("the new generation must have its own pool")
	}

	// 重复关闭是幂等的：这一代已经作废，不得再换代一次。
	next := slot.generation()
	_ = tracked.Close()
	if slot.generation() != next {
		t.Fatal("a repeated close must not advance the generation again")
	}
}

// TestTrackedConnCloseKeepsNewerGeneration 验证 stale 连接被 net/http 回收时只
// 作废自己那一代：槽位已经换代时，旧连接的关闭既不清新连接的身份，也不把新池
// 顶掉。
func TestTrackedConnCloseKeepsNewerGeneration(t *testing.T) {
	old := &countingConn{}
	newConn := &countingConn{}

	slot := slotWithGenFactory()
	oldGen := slot.generation()
	oldSC := attachConn(slot, old)
	newGen := slot.newGen()
	newSC := &slotConn{c: newConn}
	newGen.conn.Store(newSC)
	slot.gen.Store(newGen)

	tracked := &trackedConn{Conn: old, gen: oldGen, self: oldSC}
	if err := tracked.Close(); err != nil {
		t.Fatalf("trackedConn.Close: %v", err)
	}

	if got := old.closes.Load(); got != 1 {
		t.Fatalf("old connection closed %d times, want 1", got)
	}
	if oldGen.conn.Load() != nil {
		t.Fatal("trackedConn.Close must clear the pointer it owns")
	}
	if slot.generation() != newGen {
		t.Fatal("a stale generation must not replace the current pool")
	}
	if newGen.conn.Load() != newSC {
		t.Fatal("trackedConn.Close must not clear a newer generation's pointer")
	}

	// 反向：旧一代的跟踪对象也不能用来清掉新一代的连接。
	stale := &trackedConn{Conn: newConn, gen: oldGen, self: newSC}
	_ = stale.Close()
	if newGen.conn.Load() != newSC {
		t.Fatal("a retired generation's identity must not clear the current connection")
	}
}

// newH2Server 启动一个记录连接数的真实 HTTP/2 测试服务器。
func newH2Server(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 先读满 4 字节请求体，使客户端写入 bootstrap 记录时连接必然已经建立。
		buf := make([]byte, 4)
		_, _ = io.ReadFull(r.Body, buf)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &conns
}

func newRecoveryTransport(t *testing.T, serverURL, probeToken string) transport.Transport {
	t.Helper()
	tr, err := New(Config{
		ServerURL:    serverURL,
		TLSConfig:    &utls.Config{InsecureSkipVerify: true, NextProtos: sharedconfig.NextProtos},
		MaxSlotCount: 1,
		Timeout:      time.Second,
		ProbeToken:   probeToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// TestHTTP2Transport_InvalidateConnForcesNewConnection 验证端到端效果：判死路径
// （失效连接 → 关闭流 → 等本流 RoundTrip 收敛 → 丢弃空闲连接，见 client/proxy
// 的 settleDeadStream）之后，下一次 Open 必然建立一条新的底层连接
// （httptest 的 ConnState 计数）。
//
// 保证来自判死本身：InvalidateConn 在关掉底层连接的同时换掉整个连接池
// （transportSlot.advanceGeneration），下一次 Open 只能拨号。后面的收敛等待与
// CloseIdle() 照生产顺序保留，但结论不再依赖它们的收敛时机——那条依赖时序的
// 版本在 CI 上偶发失败（#226），窗口固定后的确定性版本见
// TestHTTP2Transport_InvalidateConnReplacesPool。
func TestHTTP2Transport_InvalidateConnForcesNewConnection(t *testing.T) {
	srv, conns := newH2Server(t)
	tr := newRecoveryTransport(t, srv.URL, "")

	open := func() transport.Stream {
		t.Helper()
		stream, err := tr.Open(context.Background(), transport.OpenRequest{
			Endpoint:     sharedconfig.EndpointTCP,
			Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
			HighPriority: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return stream
	}

	first := open()
	if _, err := first.Write([]byte("abcd")); err != nil {
		t.Fatalf("write bootstrap record: %v", err)
	}
	inv, ok := first.(transport.ConnInvalidator)
	if !ok {
		t.Fatal("http2Stream must implement transport.ConnInvalidator")
	}
	inv.InvalidateConn()
	_ = first.Close()

	// 判死路径在 CloseIdle() 之前等待本流收敛（见 client/proxy.settleDeadStream）。
	// 判死换连接已由 InvalidateConn 换池保证，这一步只是照生产顺序收敛本流。
	awaitResponse(t, first, time.Second)
	tr.CloseIdle()

	second := open()
	defer second.Close() //nolint:errcheck
	if _, err := second.Write([]byte("abcd")); err != nil {
		t.Fatalf("write on the second stream: %v", err)
	}
	_, _ = io.Copy(io.Discard, second)

	if got := conns.Load(); got < 2 {
		t.Fatalf("server saw %d connections, want at least 2 after invalidation", got)
	}
}

// awaitResponse 等待流的 RoundTrip 结果落定（有界）。
func awaitResponse(t *testing.T, stream transport.Stream, timeout time.Duration) {
	t.Helper()
	ra, ok := stream.(transport.ResponseAwaiter)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = ra.AwaitResponse(ctx)
}

// TestHTTP2Transport_DoesNotImplementOptionalInterfacesWhenUnprobed 验证未配置探测
// 令牌时传输层仍提供判活接口，但如实报告"无法判定"（调用方按判死处理）。
func TestHTTP2Transport_AwaitAndLivenessWiring(t *testing.T) {
	srv, _ := newH2Server(t)
	tr := newRecoveryTransport(t, srv.URL, "")

	stream, err := tr.Open(context.Background(), transport.OpenRequest{
		Endpoint:     sharedconfig.EndpointTCP,
		Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
		HighPriority: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close() //nolint:errcheck

	if _, ok := stream.(transport.ResponseAwaiter); !ok {
		t.Fatal("http2Stream must implement transport.ResponseAwaiter")
	}
	cl, ok := stream.(transport.ConnLiveness)
	if !ok {
		t.Fatal("http2Stream must implement transport.ConnLiveness")
	}
	if alive, known := cl.ConnAlive(context.Background()); known || alive {
		t.Fatalf("ConnAlive = (%v, %v), want (false, false) without a probe token", alive, known)
	}
}

// TestHTTP2Stream_CloseClosesLateResponseBody 覆盖 §4.3 的小修复：无论流先被关闭
// 还是响应先到达，未曾交付给调用方的响应体都必须被关闭，不遗留无人读取的 HTTP/2 流。
func TestHTTP2Stream_CloseClosesLateResponseBody(t *testing.T) {
	newBody := func() *countingReadCloser {
		return &countingReadCloser{ReadCloser: io.NopCloser(strings.NewReader("late"))}
	}

	t.Run("close before response", func(t *testing.T) {
		s := newRecoveryStream(t)
		body := newBody()
		_ = s.Close()
		s.deliver(roundTripResult{resp: &http.Response{StatusCode: http.StatusOK, Body: body}})

		if got := body.closed.Load(); got != 1 {
			t.Fatalf("late response body closed %d times, want 1", got)
		}
		if _, err := s.Read(make([]byte, 4)); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Read = %v, want io.ErrClosedPipe on an abandoned stream", err)
		}
	})

	t.Run("close after response", func(t *testing.T) {
		s := newRecoveryStream(t)
		body := newBody()
		s.deliver(roundTripResult{resp: &http.Response{StatusCode: http.StatusOK, Body: body}})

		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if got := body.closed.Load(); got != 1 {
			t.Fatalf("undelivered response body closed %d times, want 1", got)
		}
	})
}

type countingReadCloser struct {
	io.ReadCloser
	closed atomic.Int32
}

func (c *countingReadCloser) Close() error {
	c.closed.Add(1)
	return c.ReadCloser.Close()
}

var (
	_ net.Conn = (*countingConn)(nil)
	_ net.Conn = (*trackedConn)(nil)
)

// TestHTTP2Transport_LivenessSharesInflightConnection 验证判活探测与在飞流共享
// 同一条 HTTP/2 连接：MaxConnsPerHost=1 时探测既不会另拨新连接（那会把死连接
// 判成活的），也不会排在在飞流的响应之后一直等到超时（那会把"服务端还在解析
// 目标域名"误判成断网）。这是 §4.4 判活语义成立的前提。
func TestHTTP2Transport_LivenessSharesInflightConnection(t *testing.T) {
	inflight := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == sharedconfig.EndpointProbe {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			return
		}
		buf := make([]byte, 4)
		_, _ = io.ReadFull(r.Body, buf)
		once.Do(func() { close(inflight) })
		<-release // 模拟服务端仍在解析目标域名：响应头迟到
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	tr := newRecoveryTransport(t, srv.URL, "dummy-probe-token")
	stream, err := tr.Open(context.Background(), transport.OpenRequest{
		Endpoint:     sharedconfig.EndpointTCP,
		Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
		HighPriority: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close() //nolint:errcheck

	if _, err := stream.Write([]byte("abcd")); err != nil {
		t.Fatalf("write bootstrap record: %v", err)
	}
	select {
	case <-inflight:
	case <-time.After(2 * time.Second):
		t.Fatal("the server never received the in-flight request")
	}

	cl, ok := stream.(transport.ConnLiveness)
	if !ok {
		t.Fatal("http2Stream must implement transport.ConnLiveness")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	start := time.Now()
	alive, known := cl.ConnAlive(ctx)
	if !known || !alive {
		t.Fatalf("ConnAlive = (%v, %v), want (true, true) while a stream is in flight", alive, known)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("liveness probe took %v, want it served concurrently on the shared connection", elapsed)
	}
}

// laggingConn 把"底层连接已关闭"这个错误扣在 h2 readLoop 之外：真实实现里，
// ClientConn 只有在它自己的一次读返回错误之后才会走 cleanup（标记已关闭、把
// 自己移出连接池）。扣住这个错误就等价于"readLoop 还没有被调度到"——这是 CI 上
// 偶发失败的那段窗口，也是判死路径唯一无法自己消除的时序：写路径的通知同样
// 依赖某个 goroutine 跑到 cc.Close()。
type laggingConn struct {
	net.Conn
	closed  atomic.Bool
	release chan struct{}
}

func (c *laggingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c *laggingConn) Read(p []byte) (int, error) {
	if c.closed.Load() {
		<-c.release
		return 0, net.ErrClosed
	}
	n, err := c.Conn.Read(p)
	if err != nil && c.closed.Load() {
		<-c.release
	}
	return n, err
}

// TestHTTP2Transport_InvalidateConnReplacesPool 是判死换连接的**确定性**回归
// 测试：把 CI 上偶发的那段窗口固定下来，验证判死之后的下一条流必定拨号建立
// 新连接（而不是等连接池自己收敛）。
//
// 窗口的两半都被固定住：
//
//   - h2 客户端栈尚未察觉连接已死（laggingConn 扣住关闭引起的读错误），池里那条
//     ClientConn 仍然自认为可用、仍可被 ReserveNewRequest 选中；
//   - 被判死的流仍然注册在那条 ClientConn 上（服务端一直读它的请求体：既不结束
//     也不重置它），因此 CloseIdleConnections 里的 closeIfIdle 只会空转——连接
//     不会因为"空闲"而被回收。
//
// 在这种状态下，"CloseIdle() 之后池会自己收敛"这条路必然失效：下一条流会被交给
// 那条已经关闭的连接，引导记录写入再也回不来（issue #226 里是撞上已关闭的 pipe）。
// transportSlot.advanceGeneration 把保证变成结构性的——因此这里即使照生产判死路径调用
// CloseIdle()，也不再看它的收敛结果。
func TestHTTP2Transport_InvalidateConnReplacesPool(t *testing.T) {
	const bootstrapSalt = "dGVzdHNhbHR0ZXN0c2FsdA"

	var requests atomic.Int32
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		buf := make([]byte, 4)
		_, _ = io.ReadFull(r.Body, buf)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		// 显式冲刷：Go 的 h2 服务端要等 handler 返回才提交响应，而这里要一直
		// 挂着不返回（请求体不结束，服务端就不会结束或重置这条流，客户端连接上
		// 的 streams 集合因此始终保持非空）。
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	var dials atomic.Int32
	tr, err := New(Config{
		ServerURL:    srv.URL,
		TLSConfig:    &utls.Config{InsecureSkipVerify: true, NextProtos: sharedconfig.NextProtos},
		MaxSlotCount: 1,
		Timeout:      time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			dials.Add(1)
			return &laggingConn{Conn: c, release: release}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unblock(); _ = tr.Close() })

	open := func() transport.Stream {
		t.Helper()
		stream, err := tr.Open(context.Background(), transport.OpenRequest{
			Endpoint:     sharedconfig.EndpointTCP,
			Salt:         bootstrapSalt,
			HighPriority: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return stream
	}

	// 这条流的连接被判死。它自己也没有善终（连接死了），但测试刻意不去关闭它：
	// 一旦它开始清理，清理路径会往这条死连接上写 RST_STREAM，那次写入失败就会把
	// 死讯告知 h2 栈——窗口随之关闭。这里要固定住的正是"栈还不知道"的状态。
	dead := open()
	// 测试结束（判死窗口之外）再关闭它，避免留下悬挂的流。
	t.Cleanup(func() { _ = dead.Close() })
	if _, err := dead.Write([]byte("abcd")); err != nil {
		t.Fatalf("write bootstrap: %v", err)
	}
	awaitResponse(t, dead, time.Second)

	inv, ok := dead.(transport.ConnInvalidator)
	if !ok {
		t.Fatal("http2Stream must implement transport.ConnInvalidator")
	}
	inv.InvalidateConn()
	// 照生产判死路径（client/proxy.settleDeadStream + CloseIdle）丢掉空闲连接：
	// 但它对那条已死的连接无能为力——连接上还有这条流。
	tr.CloseIdle()

	before := dials.Load()
	second := open()
	defer second.Close() //nolint:errcheck

	writeDone := make(chan error, 1)
	go func() {
		_, werr := second.Write([]byte("abcd"))
		writeDone <- werr
	}()
	var writeErr error
	select {
	case writeErr = <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the stream after invalidation was still bound to the invalidated connection " +
			"(its write never completed): the connection pool was not replaced")
	}
	if writeErr != nil {
		t.Fatalf("write on the stream after invalidation: %v", writeErr)
	}

	if got := dials.Load(); got != before+1 {
		t.Fatalf("dials after invalidation = %d, want %d: the next stream must dial a fresh connection",
			got, before+1)
	}
	// 写入成功只说明记录离开了客户端：等它在服务端被真正处理，才能确认这条流
	// 落在了一条新的、可用的连接上。
	awaitResponse(t, second, time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for requests.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("server handled %d requests, want 2 (the judged-dead one + the one after invalidation)", got)
	}
}
