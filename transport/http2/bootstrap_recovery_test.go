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
		s := &http2Stream{slot: newProbeSlot(), liveness: prober.alive}

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
		s := &http2Stream{slot: newProbeSlot(), liveness: prober.alive}

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
		s := &http2Stream{slot: newProbeSlot(), liveness: prober.alive}

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
		s := &http2Stream{slot: newProbeSlot(), liveness: prober.alive}

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
		s := &http2Stream{slot: newProbeSlot(), liveness: prober.alive}

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
	sc := &slotConn{c: conn}
	slot := &transportSlot{}
	slot.conn.Store(sc)
	return slot, sc
}

// TestHTTP2Stream_InvalidateConnClosesExactlyOnce 覆盖 §4.8(a)：同一连接上的多条
// 流并发判定死亡时，底层 Close 恰好发生一次，其余调用是无操作。
func TestHTTP2Stream_InvalidateConnClosesExactlyOnce(t *testing.T) {
	conn := &countingConn{}
	slot, sc := newCountingSlot(conn)

	const streams = 8
	streamsOnConn := make([]*http2Stream, 0, streams)
	for range streams {
		s := &http2Stream{slot: slot}
		s.connInUse.Store(sc)
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
	if slot.conn.Load() != nil {
		t.Fatal("slot conn pointer must be cleared after invalidation")
	}
}

// TestHTTP2Stream_InvalidateConnDoesNotKillNewConnection 覆盖 §4.8(b)：流记住的是
// 自己用过的那条连接，若槽位指针已经指向新连接，身份 CAS 必然失败——健康的新连接
// 不会被误杀。
func TestHTTP2Stream_InvalidateConnDoesNotKillNewConnection(t *testing.T) {
	stale := &countingConn{}
	newConn := &countingConn{}
	slot, _ := newCountingSlot(newConn)
	// 槽位现在指向新连接；流记住的仍是它当年用过的那条旧连接。
	newSC := slot.conn.Load()
	staleSC := &slotConn{c: stale}

	s := &http2Stream{slot: slot}
	s.connInUse.Store(staleSC)
	s.InvalidateConn()

	if got := newConn.closes.Load(); got != 0 {
		t.Fatalf("new connection was closed %d times, want 0", got)
	}
	if got := stale.closes.Load(); got != 0 {
		t.Fatalf("stale connection was closed %d times, want 0 (it is not the current one)", got)
	}
	if slot.conn.Load() != newSC {
		t.Fatal("slot conn pointer must keep pointing at the new connection")
	}
}

// TestHTTP2Stream_InvalidateConnWithoutSnapshotIsNoOp 覆盖 §4.8 的残余窗口：
// 流还没完成第一次 body 写（没有连接身份快照）时调用失效必须安全返回。
func TestHTTP2Stream_InvalidateConnWithoutSnapshotIsNoOp(t *testing.T) {
	conn := &countingConn{}
	slot, sc := newCountingSlot(conn)

	s := &http2Stream{slot: slot}
	s.InvalidateConn() // connInUse 为 nil

	if conn.closes.Load() != 0 {
		t.Fatal("no connection may be closed without an identity snapshot")
	}
	if slot.conn.Load() != sc {
		t.Fatal("slot conn pointer must be untouched without an identity snapshot")
	}

	noSlot := &http2Stream{}
	noSlot.InvalidateConn() // 不得 panic
}

// TestTrackedConnCloseKeepsNewerPointer 验证 net/http 自己回收连接时只清除自己的
// 指针（CAS）：若槽位已指向新连接，旧连接的关闭不得把它清空。
func TestTrackedConnCloseKeepsNewerPointer(t *testing.T) {
	old := &countingConn{}
	newConn := &countingConn{}
	slot, _ := newCountingSlot(newConn)
	newSC := slot.conn.Load()
	oldSC := &slotConn{c: old}

	tracked := &trackedConn{Conn: old, slot: slot, self: oldSC}
	if err := tracked.Close(); err != nil {
		t.Fatalf("trackedConn.Close: %v", err)
	}

	if got := old.closes.Load(); got != 1 {
		t.Fatalf("old connection closed %d times, want 1", got)
	}
	if slot.conn.Load() != newSC {
		t.Fatal("trackedConn.Close must not clear a newer slot conn pointer")
	}

	// 反过来：它仍指向自己时，关闭会清空指针。
	tracked2 := &trackedConn{Conn: old, slot: slot, self: newSC}
	_ = tracked2.Close()
	if slot.conn.Load() != nil {
		t.Fatal("trackedConn.Close must clear the pointer it owns")
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
// 顺序是必须的：InvalidateConn 只关闭底层连接，net/http 的读循环异步感知并回收
// 它；在那之前 CloseIdleConnections 仍把这条连接当作被活跃流占用而不回收，下一次
// Open 就会再次拿到它（写引导记录立即失败）。
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
