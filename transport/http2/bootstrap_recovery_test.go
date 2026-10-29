package http2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

func newRecoveryStream(t *testing.T) *http2Stream {
	t.Helper()
	s, pr := newTestStream()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = s.Close()
	})
	return s
}

// 四种结果里最要命的是"服务端拒绝"：那是结果已就绪，不是网络故障。
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

// "拿到任何响应"即活，只有不可往返才判死；没有探测令牌时报告"无法判定"。
func TestHTTP2Stream_ConnAlive(t *testing.T) {
	t.Run("probe payload counts as alive", func(t *testing.T) {
		ts, token := newProbeServer(t, testProbePayloadSize)
		prober := &slotProber{serverURL: ts.URL, token: token}
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
		prober := &slotProber{serverURL: ts.URL, token: "unused"}
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
		prober := &slotProber{serverURL: ts.URL, token: "unused"}
		s := livenessStream(newProbeSlot(), prober.alive)

		alive, ok := s.ConnAlive(context.Background())
		if !ok || !alive {
			t.Fatalf("ConnAlive = (%v, %v), want (true, true) for a fallback page", alive, ok)
		}
	})

	t.Run("unreachable server is dead", func(t *testing.T) {
		ts, token := newProbeServer(t, testProbePayloadSize)
		deadURL := ts.URL
		ts.Close()
		prober := &slotProber{serverURL: deadURL, token: token}
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
		prober := &slotProber{serverURL: ts.URL, token: "unused"}
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
		// 流还没提交到任何一代池上，没有对象可探测，只能如实报告"无法判定"。
		slot := newProbeSlot()
		prober := &slotProber{serverURL: "https://127.0.0.1:1", token: "unused"}
		s := &http2Stream{slot: slot, liveness: prober.alive}
		if alive, ok := s.ConnAlive(context.Background()); ok || alive {
			t.Fatalf("ConnAlive = (%v, %v), want (false, false) before the request is submitted", alive, ok)
		}
	})
}

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

// livenessStream 的流已提交到槽位当前一代：判活探测的对象是流自己那一代。
// "这一代没有连接就不探测"由 probe_test 覆盖，这里测的是探测结论。
func livenessStream(slot *transportSlot, liveness func(context.Context, *slotTransport) (bool, bool)) *http2Stream {
	attachConn(slot, &countingConn{})
	s := &http2Stream{slot: slot, liveness: liveness}
	if gen := slot.generation(); gen != nil {
		s.gen.Store(gen)
	}
	return s
}

func TestHTTP2Stream_InvalidateConnClosesExactlyOnce(t *testing.T) {
	conn := &countingConn{}
	slot, sc := newCountingSlot(conn)
	gen := slot.generation()

	const streams = 8
	streamsOnConn := make([]*http2Stream, 0, streams)
	for range streams {
		s := &http2Stream{slot: slot}
		s.gen.Store(gen)
		s.conn.Store(sc)
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

// 流只持有自己提交时的那一代：槽位换代并拨出新连接后，旧一代的判死既杀不掉
// 新连接，也不会动新一代的池。
func TestHTTP2Stream_InvalidateConnDoesNotKillNewConnection(t *testing.T) {
	stale := &countingConn{}
	healthy := &countingConn{}

	slot := slotWithGenFactory()
	oldGen := slot.generation()
	staleSC := attachConn(slot, stale)
	if !slot.invalidateConnIf(oldGen, staleSC, "other stream") {
		t.Fatal("the first invalidation must win")
	}
	newGen := slot.generation()
	if newGen == oldGen {
		t.Fatal("the pool must have been replaced")
	}
	healthySC := attachConn(slot, healthy)

	s := &http2Stream{slot: slot}
	s.gen.Store(oldGen)
	s.conn.Store(staleSC)
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

// net/http 在连接满流或 GOAWAY 后会于同一代里再拨一条并顶替身份。流记的是 GotConn 报给
// 它的那条，失效必须落空：否则关掉的正是同代刚拨出来的新连接。
func TestHTTP2Stream_InvalidateConnDoesNotKillSameGenerationReplacement(t *testing.T) {
	slot := slotWithGenFactory()
	gen := slot.generation()
	dead := &countingConn{}
	deadID := attachConn(slot, dead)

	s := &http2Stream{slot: slot}
	s.gen.Store(gen)
	s.conn.Store(deadID)

	replacement := &countingConn{}
	replacementID := attachConn(slot, replacement)

	s.InvalidateConn()

	if got := replacement.closes.Load(); got != 0 {
		t.Fatalf("the replacement connection was closed %d times, want 0", got)
	}
	if got := dead.closes.Load(); got != 0 {
		t.Fatalf("the dropped connection was closed %d times, want 0: net/http already let it go", got)
	}
	if slot.generation() != gen {
		t.Fatal("a failed identity CAS must keep the generation")
	}
	if gen.conn.Load() != replacementID {
		t.Fatal("the replacement must stay the generation's connection identity")
	}
}

// 一次 RoundTrip 可能因 errClientConnUnusable 带未读 body 重试并再次触发 GotConn：记最后
// 一条，失效才对着这条流真正承载的那条连接；非 *trackedConn 或 self 为空的回报不覆盖已有身份。
func TestHTTP2Stream_NoteConnKeepsTheLastConnection(t *testing.T) {
	first := &slotConn{}
	second := &slotConn{}

	s := &http2Stream{}
	s.noteConn(httptrace.GotConnInfo{Conn: &trackedConn{self: first}})
	s.noteConn(httptrace.GotConnInfo{Conn: &trackedConn{self: second}})
	if got := s.conn.Load(); got != second {
		t.Fatalf("identity = %p, want the connection of the last GotConn %p", got, second)
	}

	s.noteConn(httptrace.GotConnInfo{Conn: &countingConn{}})
	s.noteConn(httptrace.GotConnInfo{Conn: &trackedConn{}})
	if got := s.conn.Load(); got != second {
		t.Fatal("an unusable report must not overwrite the recorded identity")
	}
}

// 本流自己的 RoundTrip 从 A 重试到 B 后，B 就是它实际使用的那条连接：判死关 B。A 已被
// net/http 从这一代换掉，不再由我们关。
func TestHTTP2Stream_InvalidateConnClosesRetriedConnection(t *testing.T) {
	slot := slotWithGenFactory()
	gen := slot.generation()
	first := &countingConn{}
	firstID := attachConn(slot, first)
	retried := &countingConn{}
	retriedID := attachConn(slot, retried)

	s := &http2Stream{slot: slot}
	s.gen.Store(gen)
	s.noteConn(httptrace.GotConnInfo{Conn: &trackedConn{self: firstID}})
	s.noteConn(httptrace.GotConnInfo{Conn: &trackedConn{self: retriedID}})

	s.InvalidateConn()

	if got := retried.closes.Load(); got != 1 {
		t.Fatalf("the retried connection closed %d times, want 1", got)
	}
	if got := first.closes.Load(); got != 0 {
		t.Fatalf("the first connection closed %d times, want 0: net/http already replaced it", got)
	}
	if slot.generation() == gen {
		t.Fatal("invalidating the stream's connection must replace the generation")
	}
}

// 身份只来自 GotConn：没有它就不失效，绝不退回"这一代的当前连接"。未提交（gen 为 nil）
// 与提交了但没拿到连接（拨号阶段失败，h2 不触发 GotConn）都不能动别人的连接。
func TestHTTP2Stream_InvalidateConnWithoutIdentityIsNoOp(t *testing.T) {
	conn := &countingConn{}
	slot, sc := newCountingSlot(conn)
	gen := slot.generation()

	s := &http2Stream{slot: slot} // gen 为 nil：请求还没提交
	s.InvalidateConn()
	if conn.closes.Load() != 0 {
		t.Fatal("no connection may be closed before the request is submitted")
	}
	if slot.connIdentity() != sc {
		t.Fatal("the connection identity must be untouched")
	}

	noConn := &http2Stream{slot: slot}
	noConn.gen.Store(gen)
	noConn.InvalidateConn()
	if conn.closes.Load() != 0 {
		t.Fatal("a stream that never got a connection must not close the generation's connection")
	}
	if slot.generation() != gen || slot.connIdentity() != sc {
		t.Fatal("the generation and its connection must be untouched")
	}

	noSlot := &http2Stream{}
	noSlot.InvalidateConn()
}

// "代 == 连接"：net/http 回收连接后这一代连同连接身份一起作废，下一条流只能拨号。
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

	next := slot.generation()
	_ = tracked.Close()
	if slot.generation() != next {
		t.Fatal("a repeated close must not advance the generation again")
	}
}

// blockingCloseConn 的 Close 阻塞到 unblock，把"关闭还没完成"的窗口稳定留在测试里。
type blockingCloseConn struct {
	net.Conn
	closeStarted chan struct{}
	release      chan struct{}
	startOnce    sync.Once
	releaseOnce  sync.Once
}

func newBlockingCloseConn() *blockingCloseConn {
	return &blockingCloseConn{closeStarted: make(chan struct{}), release: make(chan struct{})}
}

func (c *blockingCloseConn) Close() error {
	c.startOnce.Do(func() { close(c.closeStarted) })
	<-c.release
	return nil
}

func (c *blockingCloseConn) unblock() { c.releaseOnce.Do(func() { close(c.release) }) }

// 关闭一条连接时必须先作废这一代再关底层连接：uTLS 的 Close 会先发 close_notify，对端不响应
// 时最坏要等到写截止时间（5s）；这段时间里迟到的拨号只要还看得到旧身份，就会在同一代里再拨
// 一条（second_conn_in_generation）。
func TestTrackedConnCloseRetiresBeforeClosing(t *testing.T) {
	conn := newBlockingCloseConn()
	t.Cleanup(conn.unblock)

	slot := slotWithGenFactory()
	gen := slot.generation()
	sc := attachConn(slot, conn)

	closed := make(chan struct{})
	go func() {
		_ = (&trackedConn{Conn: conn, gen: gen, self: sc}).Close()
		close(closed)
	}()

	select {
	case <-conn.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("the underlying connection was never closed")
	}

	if slot.generation() == gen {
		t.Fatal("the generation must be retired before the connection is closed")
	}
	if prev := gen.conn.Swap(&slotConn{c: &countingConn{}}); prev != nil {
		t.Fatal("a dial completing during Close would still see the retired connection")
	}

	conn.unblock()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not return after the connection was released")
	}
}

// stale 连接被回收时只作废自己那一代，既不清新连接的身份，也不把新池顶掉。
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

	stale := &trackedConn{Conn: newConn, gen: oldGen, self: newSC}
	_ = stale.Close()
	if newGen.conn.Load() != newSC {
		t.Fatal("a retired generation's identity must not clear the current connection")
	}
}

func newH2Server(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		TLSConfig:    &utls.Config{InsecureSkipVerify: true, NextProtos: config.NextProtos},
		MaxSlotCount: 1,
		Timeouts:     config.Timeouts{Base: time.Second},
		ProbeToken:   probeToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// 判死之后下一次 Open 必然建立新的底层连接：InvalidateConn 在关连接的同时换掉整个池
// （transportSlot.advanceGeneration），结论不依赖连接池自己收敛的时机（#226 就是那样偶发失败的）。
func TestHTTP2Transport_InvalidateConnForcesNewConnection(t *testing.T) {
	srv, conns := newH2Server(t)
	tr := newRecoveryTransport(t, srv.URL, "")

	open := func() transport.Stream {
		t.Helper()
		stream, err := tr.Open(context.Background(), transport.OpenRequest{
			Endpoint:     config.EndpointTCP,
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

func TestHTTP2Transport_AwaitAndLivenessWiring(t *testing.T) {
	srv, _ := newH2Server(t)
	tr := newRecoveryTransport(t, srv.URL, "")

	stream, err := tr.Open(context.Background(), transport.OpenRequest{
		Endpoint:     config.EndpointTCP,
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

// 无论流先关闭还是响应先到达，未曾交付给调用方的响应体都必须关闭，
// 否则遗留无人读取的 HTTP/2 流。
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

// 判活探测与在飞流共享同一条连接：MaxConnsPerHost=1 时另拨一条会把死连接判成活，
// 排在在飞流响应之后又会把"服务端还在解析域名"误判成断网。
func TestHTTP2Transport_LivenessSharesInflightConnection(t *testing.T) {
	inflight := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == config.EndpointProbe {
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
		Endpoint:     config.EndpointTCP,
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

// laggingConn 扣住"连接已关闭"的读错误，等价于 readLoop 还没被调度到：
// 真实 ClientConn 只有在自己的读返回错误之后才会 cleanup。
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

// 判死换连接的确定性回归：h2 栈还没察觉连接已死、被判死的流仍注册在那条 ClientConn 上，
// 此时"CloseIdle() 之后池会自己收敛"必然失效，下一条流会被交给已关闭的连接（#226）。
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
		// h2 服务端要等 handler 返回才提交响应，因此这里一直挂着：请求体不结束，
		// 服务端就不会结束或重置这条流，客户端连接上的 streams 集合始终非空。
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
		TLSConfig:    &utls.Config{InsecureSkipVerify: true, NextProtos: config.NextProtos},
		MaxSlotCount: 1,
		Timeouts:     config.Timeouts{Base: time.Second},
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
			Endpoint:     config.EndpointTCP,
			Salt:         bootstrapSalt,
			HighPriority: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return stream
	}

	// 刻意不关闭这条流：它一开始清理就会往死连接上写 RST_STREAM，写入失败会把死讯告知
	// h2 栈，窗口随之关闭。
	dead := open()
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
	// 照生产判死路径调用 CloseIdle()，但它对这条已死的连接无能为力（上面还有流）。
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
	// 写入成功只说明记录离开了客户端，还要等它在服务端被处理才能确认落在新连接上。
	awaitResponse(t, second, time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for requests.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("server handled %d requests, want 2 (the judged-dead one + the one after invalidation)", got)
	}
}

// 服务端每连接只允许一条并发流时，同一槽位上的第二条流会让 net/http 在同一张池里再拨一条
// （先丢掉 persistConn、让出 MaxConnsPerHost 计数再重拨）。传输层必须把它记成
// stats.SecondConnInGeneration + 一条 Warn，而不是静默覆盖连接身份。
func TestHTTP2Transport_SecondConnInGenerationIsObservable(t *testing.T) {
	var conns atomic.Int32
	var requests atomic.Int32
	started := make(chan struct{}, 2)
	// 除热身请求外的 handler 一直占住服务端唯一的流槽：用 sleep 占槽位会把结论交给时序，
	// CI 负载高时第一条流先返回、第二条流复用同一连接，计数就为 0。
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r.Body, buf); err != nil {
			return
		}
		// 第一条是热身请求：客户端读到它的响应说明服务端的 SETTINGS（maxConcurrentStreams=1）
		// 已被应用，否则第二条流可能在还没学到上限时就被发到同一条连接上（Windows ARM64 CI
		// 上实际踩到过：第二条流 2s 都没到达服务端）。
		if requests.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("ok"))
			return
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.Config.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: 1}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	stats.ResetCounters()
	tr := newRecoveryTransport(t, srv.URL, "")

	open := func() transport.Stream {
		t.Helper()
		stream, err := tr.Open(context.Background(), transport.OpenRequest{
			Endpoint:     config.EndpointTCP,
			Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
			HighPriority: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write([]byte("abcd")); err != nil {
			t.Fatalf("write bootstrap record: %v", err)
		}
		return stream
	}

	warmup := open()
	_, _ = io.Copy(io.Discard, warmup)
	_ = warmup.Close()

	first := open()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first stream never reached the server")
	}

	second := open()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the second stream never reached the server")
	}

	if got := stats.Collect().SecondConnInGeneration; got < 1 {
		t.Fatalf("second dial in one generation was not counted (got %d)", got)
	}
	if got := conns.Load(); got < 2 {
		t.Fatalf("server saw %d connections, want at least 2 (one per concurrent stream)", got)
	}

	unblock()
	_, _ = io.Copy(io.Discard, first)
	_, _ = io.Copy(io.Discard, second)
	_ = first.Close()
	_ = second.Close()
}
