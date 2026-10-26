package handler

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
)

// deadlineRecorder 记录 ResponseController 设置的写截止时间，用来断言收尾只在超预算时
// 才复位流：正常收尾设置 deadline 会让慢速但仍在推进的尾部被截断。
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines chan time.Time
}

func newDeadlineRecorder() *deadlineRecorder {
	return &deadlineRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		deadlines:        make(chan time.Time, 1),
	}
}

func (r *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	r.deadlines <- deadline
	return nil
}

type teardownTestShaper struct {
	// block 非 nil 时 Close 一直阻塞到它被关闭，模拟收尾排在卡住的响应写后面。
	block   chan struct{}
	frames  []protocol.Frame
	flushed bool
}

func (s *teardownTestShaper) PushFrame(f protocol.Frame) error {
	s.frames = append(s.frames, f)
	return nil
}

func (s *teardownTestShaper) PushData([]byte) error { return nil }

func (s *teardownTestShaper) Flush() error {
	s.flushed = true
	return nil
}

func (s *teardownTestShaper) Close() error {
	if s.block != nil {
		<-s.block
	}
	return nil
}

// TestTeardownSessionLeavesFastTeardownAlone 固定正常收尾不设写截止时间：reset 会让
// 已经排队但尚未送达的响应尾部被截断。
func TestTeardownSessionLeavesFastTeardownAlone(t *testing.T) {
	h := &ProxyHandler{teardownGrace: time.Second}
	rec := newDeadlineRecorder()
	sh := &teardownTestShaper{}

	h.teardownSession(http.NewResponseController(rec), sh, streamResult{})

	select {
	case deadline := <-rec.deadlines:
		t.Fatalf("a fast teardown set a write deadline %v, want none", deadline)
	default:
	}
	if len(sh.frames) != 0 {
		t.Fatalf("a clean result pushed %+v, want no frames", sh.frames)
	}
}

// TestTeardownSessionSendsRSTForFailure 固定失败结果的帧语义：收尾集中到 serveSession
// 之后，RST 仍然必须排在 Close 之前推出并 flush。
func TestTeardownSessionSendsRSTForFailure(t *testing.T) {
	sh := &teardownTestShaper{}
	h := &ProxyHandler{teardownGrace: time.Second}

	h.teardownSession(http.NewResponseController(newDeadlineRecorder()), sh, streamResult{Err: errors.New("boom")})

	if len(sh.frames) != 1 || sh.frames[0].Type != protocol.FrameRST {
		t.Fatalf("frames = %+v, want exactly one RST", sh.frames)
	}
	if !sh.flushed {
		t.Fatal("the RST must be flushed before the shaper is closed")
	}
}

// TestTeardownSessionResetsStreamWhenCloseBlocks 守住预算：收尾卡在响应写上时必须复位
// 流，否则 handler goroutine 会随客户端一起滞留。
func TestTeardownSessionResetsStreamWhenCloseBlocks(t *testing.T) {
	h := &ProxyHandler{teardownGrace: 20 * time.Millisecond}
	rec := newDeadlineRecorder()
	release := make(chan struct{})
	sh := &teardownTestShaper{block: release}

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.teardownSession(http.NewResponseController(rec), sh, streamResult{})
	}()

	select {
	case deadline := <-rec.deadlines:
		// 必须立即复位：再给一个未来的 deadline 等于把收尾继续往后推。
		if deadline.After(time.Now()) {
			t.Fatalf("write deadline = %v, want an immediate reset", deadline)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a blocked teardown did not reset the stream within its budget")
	}

	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("teardown did not return after the stream was reset")
	}
}

// firehoseConn 是永不 EOF 的目标连接：只要服务端还在读，它就持续产生响应数据。
type firehoseConn struct {
	closed chan struct{}
	once   sync.Once
	read   atomic.Int64
}

func newFirehoseConn() *firehoseConn {
	return &firehoseConn{closed: make(chan struct{})}
}

func (c *firehoseConn) Read(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.read.Add(int64(len(p)))
	return len(p), nil
}

func (c *firehoseConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *firehoseConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *firehoseConn) LocalAddr() net.Addr { return &net.TCPAddr{} }
func (c *firehoseConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(testPublicV4), Port: 443}
}
func (c *firehoseConn) SetDeadline(time.Time) error      { return nil }
func (c *firehoseConn) SetReadDeadline(time.Time) error  { return nil }
func (c *firehoseConn) SetWriteDeadline(time.Time) error { return nil }

// TestServeHTTP_HandlerExitsWhenResponseIsNotRead 复现 #278：客户端持有连接但不读该流的
// 响应，h2 流控窗口耗尽后响应写停住；relay 空闲超时返回时收尾（RST + shaper Close）排在
// 写锁后面，因此必须在收尾预算内复位该流，handler 才能退出。
func TestServeHTTP_HandlerExitsWhenResponseIsNotRead(t *testing.T) {
	const (
		idleTimeout   = 100 * time.Millisecond
		teardownGrace = 100 * time.Millisecond
		// 客户端只给很小的流控窗口，响应写很快就停在等待对端读的流控上。
		clientWindow = 8 << 10
	)

	masterKey := []byte("0123456789abcdef0123456789abcdef")
	deps := defaultOutboundDeps()
	deps.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(testPublicV4)}, nil
	}
	h := newProxyHandlerWithDeps(ProxyHandlerConfig{
		MasterKey:        masterKey,
		AllowedMethods:   []string{protocol.MethodAES256GCM.String()},
		Timeouts:         config.Timeouts{Base: time.Second, StreamIdle: idleTimeout},
		HandshakeTimeout: time.Second,
		Shaper:           shaper.Config{BatchWindowMS: 1},
	}, deps)
	h.teardownGrace = teardownGrace

	target := newFirehoseConn()
	h.tcp.dialContext = func(context.Context, string, string) (net.Conn, error) { return target, nil }

	handlerDone := make(chan struct{})
	srv := newRejectTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		h.ServeHTTP(w, r)
	}))

	tr := newRejectTestClient(t)
	tr.HTTP2 = &http.HTTP2Config{
		MaxReceiveBufferPerStream:     clientWindow,
		MaxReceiveBufferPerConnection: 64 << 10,
	}

	saltB64, bootstrap := buildBootstrapRecord(t, masterKey, config.EndpointTCP,
		protocol.ProtoTCP, protocol.MethodAES256GCM, testPublicV4+":443")

	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() }) //nolint:errcheck
	req, err := http.NewRequest(http.MethodPost, srv.URL+config.EndpointTCP, pr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("x-es", saltB64)

	// 请求体只写 bootstrap 记录后保持打开：客户端既不发 FIN 也不读响应。
	go func() {
		_, _ = pw.Write(bootstrap)
	}()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() }) //nolint:errcheck

	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not exit while the client kept the response unread")
	}
	if target.read.Load() == 0 {
		t.Fatal("the target was never read: the handler did not reach the relay")
	}
}
