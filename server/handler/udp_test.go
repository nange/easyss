package handler

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
)

// deadlineConn 模拟真实 UDP socket 的读取语义：Read 一直阻塞，直到一个被
// 推迟的读取截止时间到期（SetReadDeadline 被视为"截止时间已到"），或连接被
// 关闭（net.ErrClosed）。它用来断言会话关闭会主动把截止时间提前，使读取
// goroutine 立即退出，而不是滞留等满一个完整的空闲超时。
type deadlineConn struct {
	closed   chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
	woke     bool
}

func newDeadlineConn() *deadlineConn {
	return &deadlineConn{closed: make(chan struct{})}
}

func (c *deadlineConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *deadlineConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *deadlineConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// SetReadDeadline 记录截止时间（并唤醒阻塞中的 Read——真实 socket 在截止时间
// 到期时会返回 os.ErrDeadlineExceeded）。
func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	if !t.IsZero() && !t.After(time.Now()) {
		c.woke = true
	}
	c.mu.Unlock()
	return nil
}

// wokeUp 报告是否有一个被设为"此刻或更早"的读取截止时间——即会话是否主动
// 提前了截止时间来解除读取侧的阻塞。
func (c *deadlineConn) wokeUp() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.woke
}

func (c *deadlineConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero, Port: 1} }
func (c *deadlineConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
}
func (c *deadlineConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *deadlineConn) SetWriteDeadline(time.Time) error { return nil }

// blockingConn 的 Read 只在 Close 之后返回：它让客户端帧读取 goroutine 真正
// 停在 ReadFrame 上，从而断言会话收尾确实解除了那次阻塞。
type blockingConn struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingConn() *blockingConn {
	return &blockingConn{closed: make(chan struct{})}
}

func (c *blockingConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *blockingConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *blockingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *blockingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *blockingConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *blockingConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingConn) SetWriteDeadline(time.Time) error { return nil }

// isClosed 报告 cancelRead 是否已经关闭了它。
func (c *blockingConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// newUDPSessionFixture 组装一个可控的 udpSession：客户端帧读取侧来自 body，
// s2c 写入落到内存缓冲，目标侧由调用方提供。
func newUDPSessionFixture(t *testing.T, targetConn net.Conn, target string, idleTimeout time.Duration, np *nextproxy.NextProxy, body io.Reader) (*udpSession, *countingWriter) {
	t.Helper()

	sk, err := crypto.NewStreamKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 16),
		sharedconfig.EndpointUDP,
	)
	if err != nil {
		t.Fatal(err)
	}
	dr, err := sk.NewReader(body, crypto.DirC2S, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	out := &countingWriter{}
	s2cWriter, err := sk.NewWriter(out, crypto.DirS2C, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}

	s := newUDPSession(udpSessionConfig{
		conn:        targetConn,
		remote:      target,
		target:      target,
		dr:          dr,
		s2c:         shaper.New(s2cWriter, shaper.Config{BatchWindowMS: 1}),
		idleTimeout: idleTimeout,
		nextProxy:   np,
	})
	if closer, ok := body.(io.Closer); ok {
		s.cancelRead = func() { _ = closer.Close() }
	}
	if np != nil {
		s.shouldProxy = func(string) bool { return false }
	}
	return s, out
}

// countingWriter 是只给单测用的小型 io.Writer（crypto.RecordWriter 只需要它），
// 同时记录写入量，用于断言客户端方向确实收到了数据。
type countingWriter struct {
	mu  sync.Mutex
	buf []byte
}

func (b *countingWriter) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *countingWriter) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buf)
}

// TestUDPSessionCloseExitsReaderGoroutines 是阶段 2 的验收回归：会话关闭后，
// 两个读取 goroutine 必须在"一个读截止时间"内退出，而不是滞留在阻塞的 Read
// 上等满一个完整的空闲超时（默认 60s）。close 会等待读取 goroutine 退出后才
// 返回，而这里的目标连接只在被关闭后才让 Read 返回、客户端帧读取也停在
// cancelRead 之后，因此断言窗口（1s）远小于空闲超时（30s）时，只有 close
// 主动解除了两处阻塞才能通过。它同时固定 run 必须观察 done：客户端与目标
// 两侧都沉默时，外部 close 是结束会话的唯一信号。
func TestUDPSessionCloseExitsReaderGoroutines(t *testing.T) {
	conn := newDeadlineConn()
	body := newBlockingConn()
	s, _ := newUDPSessionFixture(t, conn, "8.8.8.8:53", 30*time.Second, nil, body)

	runDone := make(chan streamResult, 1)
	go func() { runDone <- s.run() }()

	// 让两个读取 goroutine 都进入阻塞状态。
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	s.close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("close waited %v; the reader goroutines must exit within one read deadline", elapsed)
	}
	if !conn.wokeUp() {
		t.Fatal("close must pull the target read deadline to now so the reader returns immediately")
	}

	select {
	case res := <-runDone:
		if res.needsRST() {
			t.Fatalf("run returned %v, want a clean end after close", res.Err)
		}
	case <-time.After(time.Second):
		t.Fatal("run did not return after close")
	}
	if !body.isClosed() {
		t.Fatal("close did not unblock the client frame reader (cancelRead was not called)")
	}
}

// TestUDPSessionFINEndsStream 固定终止判定只有一处：客户端发来 FIN 时会话
// 立即以"正常结束"收尾（Err 为 nil，不触发 RST），而不是继续等到空闲超时。
func TestUDPSessionFINEndsStream(t *testing.T) {
	conn := newDeadlineConn()
	body := newFrameReader(t, []protocol.Frame{protocol.NewFrameFIN()})
	s, _ := newUDPSessionFixture(t, conn, "8.8.8.8:53", 30*time.Second, nil, body)

	result := s.run()
	if result.needsRST() {
		t.Fatalf("a client FIN should end the stream cleanly, got %v", result.Err)
	}
	if result.TimedOut {
		t.Fatal("a client FIN must not be reported as an idle timeout")
	}
}

// TestUDPSessionIdleTimeoutEndsStream 固定空闲超时路径：没有任何帧往来的会话
// 在空闲超时后以 TimedOut 收尾（而不是错误）。
func TestUDPSessionIdleTimeoutEndsStream(t *testing.T) {
	conn := newDeadlineConn()
	body := newBlockingConn()
	s, _ := newUDPSessionFixture(t, conn, "8.8.8.8:53", 60*time.Millisecond, nil, body)

	start := time.Now()
	result := s.run()
	if !result.TimedOut {
		t.Fatalf("an idle session should end with TimedOut, got %+v", result)
	}
	if result.needsRST() {
		t.Fatalf("an idle timeout is a normal end, got %v", result.Err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the idle timeout took %v", elapsed)
	}
}

// TestUDPSessionTargetReadErrorIsReported 固定真实故障路径：目标连接报出
// 非拆连接错误时会话以该错误结束（并因此触发 RST），而拆连接错误会被归一化
// 为正常结束，不会刷 Error 日志。
func TestUDPSessionTargetReadErrorIsReported(t *testing.T) {
	boom := errors.New("udp read: connection refused")
	conn := newErrorConn(boom)
	s, _ := newUDPSessionFixture(t, conn, "8.8.8.8:53", time.Second, nil, newBlockingConn())

	result := s.run()
	if !errors.Is(result.Err, boom) {
		t.Fatalf("result.Err = %v, want the target read failure", result.Err)
	}
	if !result.needsRST() {
		t.Fatal("a real target failure must ask for an RST")
	}
}

// errorConn 的 Read 立即返回给定的错误。
type errorConn struct{ err error }

func newErrorConn(err error) *errorConn { return &errorConn{err: err} }

func (c *errorConn) Read([]byte) (int, error)         { return 0, c.err }
func (c *errorConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *errorConn) Close() error                     { return nil }
func (c *errorConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *errorConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *errorConn) SetDeadline(time.Time) error      { return nil }
func (c *errorConn) SetReadDeadline(time.Time) error  { return nil }
func (c *errorConn) SetWriteDeadline(time.Time) error { return nil }

// TestUDPSessionLearnsDNSAnswers 固定 UDP 上的动态路由学习：会话看到指向
// 自定义域名的 DNS 查询后，用同一会话里返回的 DNS 应答喂养 next proxy 的
// 路由表（CNAME 目标与解析出的 IP）。学习状态由主 goroutine 独占，这里直接
// 驱动它的两个入口（detectDNSQuery / learnFromDNS）。
func TestUDPSessionLearnsDNSAnswers(t *testing.T) {
	np, err := nextproxy.New("socks5://proxy.example.com:1080", true, false)
	if err != nil {
		t.Fatal(err)
	}
	np.AddDomain("cdn.example.com")

	s, _ := newUDPSessionFixture(t, newDeadlineConn(), "8.8.8.8:53", time.Second, np, newBlockingConn())

	query := &dns.Msg{}
	query.SetQuestion("cdn.example.com.", dns.TypeA)
	qb, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	s.detectDNSQuery(protocol.NewFrameDATAGRAM(qb))
	if !s.dns.intercept {
		t.Fatal("a DNS query for a custom domain must enable answer interception")
	}

	resp := &dns.Msg{}
	resp.SetReply(query)
	resp.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "cdn.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "edge.example.net."},
		&dns.A{Hdr: dns.RR_Header{Name: "edge.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("93.184.216.34")},
	}
	ps, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	s.learnFromDNS(udpDatagram{payload: ps, dnsMsg: resp})

	if !np.ShouldProxy("93.184.216.34") {
		t.Fatal("the A record from the DNS answer was not learned by the next proxy")
	}
	if !np.ShouldProxy("edge.example.net") {
		t.Fatal("the CNAME target from the DNS answer was not learned by the next proxy")
	}

	// 未启用拦截（没有见过 DNS 查询）时不得学习。
	other, err := nextproxy.New("socks5://proxy.example.com:1080", true, false)
	if err != nil {
		t.Fatal(err)
	}
	other.AddDomain("cdn.example.com")
	s2, _ := newUDPSessionFixture(t, newDeadlineConn(), "8.8.8.8:53", time.Second, other, newBlockingConn())
	s2.learnFromDNS(udpDatagram{payload: ps, dnsMsg: resp})
	if other.ShouldProxy("93.184.216.34") {
		t.Fatal("without an observed DNS query the session must not learn answers")
	}
}

// TestUDPSessionObserveClientFrame 固定客户端帧的分类：DATAGRAM 写入目标后
// 会话继续，FIN/RST 正常结束，PADDING/COVER 被忽略但不结束会话。
func TestUDPSessionObserveClientFrame(t *testing.T) {
	s, _ := newUDPSessionFixture(t, newDeadlineConn(), "8.8.8.8:53", time.Second, nil, newBlockingConn())

	tests := []struct {
		name  string
		frame protocol.Frame
		alive bool
	}{
		{"datagram", protocol.NewFrameDATAGRAM([]byte("payload")), true},
		{"padding", protocol.NewFramePADDING(8), true},
		{"fin", protocol.NewFrameFIN(), false},
		{"rst", protocol.NewFrameRST(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alive, err := s.observeClientFrame(tt.frame)
			if err != nil {
				t.Fatalf("observeClientFrame: %v", err)
			}
			if alive != tt.alive {
				t.Fatalf("alive = %v, want %v", alive, tt.alive)
			}
		})
	}
}

// newFrameReader 把一批帧编码成客户端记录流，供会话读取。
func newFrameReader(t *testing.T, frames []protocol.Frame) io.Reader {
	t.Helper()
	sk, err := crypto.NewStreamKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 16),
		sharedconfig.EndpointUDP,
	)
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	w, err := sk.NewWriter(&buf, crypto.DirC2S, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	var plain []byte
	for _, f := range frames {
		plain = protocol.AppendFrame(plain, f)
	}
	if err := w.WriteRecord(plain); err != nil {
		t.Fatal(err)
	}
	return strings.NewReader(buf.String())
}
