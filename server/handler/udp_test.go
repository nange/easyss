package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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
	"github.com/nange/easyss/v3/util"
	socks5 "github.com/xjasonlyu/tun2socks/v2/transport/socks5"
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

// oversizedReadConn 按脚本依次返回：读满整个池档位（模拟被内核截断的超大
// UDP 读）、略超预算但未截断的读、一条正常载荷；之后按截止时间返回
// os.ErrDeadlineExceeded。它让"丢弃超限数据报"的逻辑不依赖平台能否真的发送
// 16KB 的 UDP 数据报（macOS 默认 net.inet.udp.maxdgram 只有 9216）。
type oversizedReadConn struct {
	mu   sync.Mutex
	step int
}

func (c *oversizedReadConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	step := c.step
	c.step++
	c.mu.Unlock()

	switch step {
	case 0:
		return len(p), nil
	case 1:
		return udpBufSize + 1, nil
	case 2:
		return copy(p, []byte("normal-response")), nil
	default:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *oversizedReadConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *oversizedReadConn) Close() error                     { return nil }
func (c *oversizedReadConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *oversizedReadConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *oversizedReadConn) SetDeadline(time.Time) error      { return nil }
func (c *oversizedReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *oversizedReadConn) SetWriteDeadline(time.Time) error { return nil }

// TestUDPSessionReadFromTargetDropsOversized 固定目标侧的读循环不会把被内核
// 截断的数据报（n == 读缓冲长度）或超过预算的数据报转发给客户端；读循环必须
// 跳过它们，只推送随后那条正常的载荷。
func TestUDPSessionReadFromTargetDropsOversized(t *testing.T) {
	s := newUDPSession(udpSessionConfig{
		conn:        &oversizedReadConn{},
		target:      "8.8.8.8:53",
		idleTimeout: time.Second,
		ctx:         context.Background(),
	})
	go s.readFromTarget()
	defer close(s.done)

	select {
	case res := <-s.resultCh:
		if res.err != nil {
			t.Fatalf("readFromTarget returned error %v, want the normal datagram", res.err)
		}
		if got := string(res.payload); got != "normal-response" {
			t.Fatalf("payload = %q, want %q（超限/截断的数据报必须被丢弃）", got, "normal-response")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for the normal datagram")
	}
}

// newUDPSessionFixture 组装一个可控的 udpSession：客户端帧读取侧来自 body，
// s2c 写入落到内存缓冲，目标侧由调用方提供。
//
// 目标是 53 端口时按 DNS 会话构造（dnsSession=true，出站连接由查询域名决定，
// 见 udpHandler.Handle），并装上与生产同构的 dnsRouter/dialer：测试可以替换
// s.dns.router 来固定路由判定，替换 s.dial 来固定拨号结果。
func newUDPSessionFixture(t *testing.T, targetConn net.Conn, target string, idleTimeout time.Duration, np *nextproxy.NextProxy, body io.Reader) (*udpSession, *countingWriter) {
	t.Helper()
	return newUDPSessionFixtureWithWriter(t, targetConn, target, idleTimeout, np, body, nil)
}

// newUDPSessionFixtureWithWriter 与 newUDPSessionFixture 相同，但允许把 s2c
// 记录流写到调用方提供的 sink（端到端用例需要一边跑会话一边解出推送的帧）。
func newUDPSessionFixtureWithWriter(t *testing.T, targetConn net.Conn, target string, idleTimeout time.Duration, np *nextproxy.NextProxy, body io.Reader, sink io.Writer) (*udpSession, *countingWriter) {
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
	var s2cSink io.Writer = out
	if sink != nil {
		s2cSink = sink
	}
	s2cWriter, err := sk.NewWriter(s2cSink, crypto.DirS2C, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}

	dialTimeout := sharedconfig.DialTimeout(30 * time.Second)
	directDialer := outboundDialer(dialTimeout, 0)
	d := dialer{
		nextProxy: np,
		shouldProxy: func(t string) bool {
			return np != nil && np.EnableUDP() && np.ShouldProxy(t)
		},
		direct: func(ctx context.Context, network, target string) (net.Conn, error) {
			return dialOutbound(ctx, directDialer, network, target)
		},
	}
	dnsSession := isDNSPort(target)
	var route dnsRouter
	if np != nil {
		route = udpRouteDialer{dialer: d, nextProxy: np}
	}

	s := newUDPSession(udpSessionConfig{
		conn:        targetConn,
		remote:      target,
		target:      target,
		dnsSession:  dnsSession,
		dr:          dr,
		s2c:         shaper.New(s2cWriter, shaper.Config{BatchWindowMS: 1}),
		idleTimeout: idleTimeout,
		ctx:         context.Background(),
		nextProxy:   np,
		route:       route,
		dial:        d,
	})
	if closer, ok := body.(io.Closer); ok {
		s.cancelRead = func() { _ = closer.Close() }
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
// 驱动它的两个入口（noteDNSQuery / learnFromDNS），并模拟主循环的门控：
// 只有 intercept 为真时才解析应答，否则普通中继流量不该被解析（见 maybeDNS）。
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
	s.noteDNSQuery(qb)
	if !s.dns.intercept {
		t.Fatal("the DNS query must arm answer interception")
	}
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
	// 主循环的热路径入口：自带 intercept 门控。
	s.learnFromDNS(ps)

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
	s2.learnFromDNS(ps)
	if other.ShouldProxy("93.184.216.34") {
		t.Fatal("without an observed DNS query the session must not learn answers")
	}
}

// TestUDPSessionLearnFromDNSGate 是非 DNS 中继流量（QUIC 等）的性能回归：
// 主循环的热路径只有 s.dns.intercept 为真时才会走到解析，而 learnFromDNS
// 自身也保持这道门控。这里用一个*确实能被解析成 DNS 应答*的载荷来证明
// "没解析就不学习"——若门控被去掉，解析与学习都会发生，测试即失败。
func TestUDPSessionLearnFromDNSGate(t *testing.T) {
	np, err := nextproxy.New("socks5://proxy.example.com:1080", true, false)
	if err != nil {
		t.Fatal(err)
	}
	np.AddDomain("cdn.example.com")

	s, _ := newUDPSessionFixture(t, newDeadlineConn(), "8.8.8.8:53", time.Second, np, newBlockingConn())

	query := &dns.Msg{}
	query.SetQuestion("cdn.example.com.", dns.TypeA)
	resp := &dns.Msg{}
	resp.SetReply(query)
	resp.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "cdn.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("93.184.216.34")},
	}
	msg, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	// 载荷本身是合法的 DNS 应答，唯一的差别只在门控状态。
	if s.maybeDNS(msg) == nil {
		t.Fatal("the fixture payload should be parseable as a DNS response")
	}

	if s.dns.intercept {
		t.Fatal("a fresh session must not intercept DNS answers")
	}
	s.learnFromDNS(msg)
	if np.ShouldProxy("93.184.216.34") {
		t.Fatal("an un-intercepted session must not parse or learn the datagram")
	}

	// 门控打开后同一份载荷才会被解析并学习。
	s.dns.intercept = true
	s.learnFromDNS(msg)
	if !np.ShouldProxy("93.184.216.34") {
		t.Fatal("an intercepted session must learn the DNS answer")
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

// dnsDial 是 fakeDNSRouter 记录的一次拨号。
type dnsDial struct {
	route  dnsRoute
	target string
	conn   net.Conn
}

// fakeDNSRouter 是 dnsRouter 的可控实现：路由判定按域名固定命中下一级代理，
// 拨号按顺序取出预先摆好的连接并记录调用，使"哪条查询走了哪条路"成为可断言
// 的事实，而不必真的去连下一级代理。
type fakeDNSRouter struct {
	proxyDomain string
	// proxyConns/directConns 是两条路由各自的预置连接，按先后顺序取出。
	proxyConns  []net.Conn
	directConns []net.Conn
	// dials 记录每一次拨号（两条路由都记），使"这条查询走了哪条路、有没有重拨"
	// 成为可直接断言的事实。
	dials []dnsDial
}

func (f *fakeDNSRouter) routeForDomain(domain string) dnsRoute {
	if strings.Contains(domain, f.proxyDomain) {
		return dnsRouteNextProxy
	}
	return dnsRouteDirect
}

func (f *fakeDNSRouter) dialRoute(_ context.Context, _, target, _ string, route dnsRoute) (net.Conn, string, error) {
	pool, remote := &f.directConns, "direct"
	if route.viaNextProxy() {
		pool, remote = &f.proxyConns, "socks5://proxy.example.com:1080"
	}
	if len(*pool) == 0 {
		return nil, "", fmt.Errorf("fake dns router: no more %s connections", remote)
	}
	conn := (*pool)[0]
	*pool = (*pool)[1:]
	f.dials = append(f.dials, dnsDial{route: route, target: target, conn: conn})
	return conn, remote, nil
}

// dnsTargetConn 是 DNS 会话出站连接的假实现：写入落到内存（可断言"这条查询
// 发到了哪条连接"），Close 可观测（可断言重绑拆掉了旧连接），读取则从 recv
// 通道取数据——测试用 send 模拟上游解析器的应答；没有数据时读取阻塞，与真实
// UDP socket 的等待语义一致，同时不会像 net.Pipe 那样因无人读取而卡住写入。
//
// after 闸门让测试能表达"旧连接被拆掉之后新连接才回包"这类顺序约束，reading
// 通知让测试能观察到"读取侧已经切到这条连接上"，两者都用于避免 sleep 与轮询
// 会话内部状态（那既是数据竞争，也让时序不可复现）。
type dnsTargetConn struct {
	recv    chan []byte
	closed  chan struct{}
	after   chan struct{}
	reading chan struct{}
	once    sync.Once
	mu      sync.Mutex
	writes  [][]byte
}

func newDNSTargetConn() *dnsTargetConn {
	return &dnsTargetConn{
		recv:   make(chan []byte, 4),
		closed: make(chan struct{}),
	}
}

// send 排入一条上游应答。
func (c *dnsTargetConn) send(payload []byte) { c.recv <- payload }

// releaseAfter 让本连接的读取在 gate 关闭之后才交付排队的应答。gate 为 nil 时
// 没有闸门（立即交付）。它必须在连接被交给会话之前调用。
func (c *dnsTargetConn) releaseAfter(gate chan struct{}) {
	if gate == nil {
		return
	}
	c.after = make(chan struct{})
	go func() {
		select {
		case <-gate:
			close(c.after)
		case <-c.closed:
			close(c.after)
		}
	}()
}

func (c *dnsTargetConn) Read(p []byte) (int, error) {
	if c.reading != nil {
		select {
		case c.reading <- struct{}{}:
		default:
		}
	}
	if c.after != nil {
		select {
		case <-c.after:
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	select {
	case b := <-c.recv:
		return copy(p, b), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *dnsTargetConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return len(p), nil
}

func (c *dnsTargetConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *dnsTargetConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *dnsTargetConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *dnsTargetConn) SetDeadline(time.Time) error      { return nil }
func (c *dnsTargetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *dnsTargetConn) SetWriteDeadline(time.Time) error { return nil }
func (c *dnsTargetConn) isClosed() bool                   { return !c.isOpen() }
func (c *dnsTargetConn) isOpen() bool {
	select {
	case <-c.closed:
		return false
	default:
		return true
	}
}

// writeCount 返回这条连接上收到的数据报数。
func (c *dnsTargetConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

// connRoute 返回当前连接实际使用的路由；没有连接时返回直连（零值），
// 与 dnsState.connRoute 为 nil 的语义一致。
func connRoute(s *udpSession) dnsRoute {
	if s.dns.connRoute == nil {
		return dnsRouteDirect
	}
	return *s.dns.connRoute
}

// packDNSQuery 打包一条 A 记录查询。
func packDNSQuery(t *testing.T, domain string) []byte {
	t.Helper()
	q := &dns.Msg{}
	q.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	b, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDNSSessionRoutesQueryByDomain 固定本次改动的核心：目标是 53 端口的会话
// 不在建立时拨号，而是读出 QNAME 之后按域名决定出站路由——命中下一级代理规则
// 的域名走代理，未命中的走直连，路由变化会重绑出站连接，未变化则复用。
func TestDNSSessionRoutesQueryByDomain(t *testing.T) {
	local0, local1 := newDNSTargetConn(), newDNSTargetConn()

	router := &fakeDNSRouter{proxyDomain: "google", proxyConns: []net.Conn{local0}, directConns: []net.Conn{local1}}
	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	s.dns.router = router

	// 第一条查询：域名命中下一级代理，出站连接在此时才建立。
	alive, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, "mtalk.google.com")))
	if err != nil {
		t.Fatalf("observeClientFrame: %v", err)
	}
	if !alive {
		t.Fatal("a datagram frame must keep the session alive")
	}
	if len(router.dials) != 1 {
		t.Fatalf("dials = %d, want 1 (a DNS session must dial on the first query)", len(router.dials))
	}
	if got := router.dials[0]; got.route != dnsRouteNextProxy || got.target != "8.8.8.8:53" {
		t.Fatalf("first dial = %+v, want the next-proxy route for 8.8.8.8:53", got)
	}
	if s.upstream() != local0 {
		t.Fatal("the session must send the query over the next-proxy connection")
	}

	// 第二条查询：域名未命中，路由变化 → 重绑到直连连接。
	alive, err = s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, "example.com")))
	if err != nil {
		t.Fatalf("observeClientFrame: %v", err)
	}
	if !alive {
		t.Fatal("a datagram frame must keep the session alive")
	}
	if len(router.dials) != 2 {
		t.Fatalf("dials = %d, want 2 (a route change must rebind the upstream)", len(router.dials))
	}
	if got := router.dials[1]; got.route != dnsRouteDirect {
		t.Fatalf("second dial = %+v, want the direct route", got)
	}
	if s.upstream() != local1 {
		t.Fatal("the session must rebind to the direct connection")
	}
	if s.dns.routeSel != dnsRouteDirect || connRoute(s) != dnsRouteDirect {
		t.Fatalf("routeSel = %v, connRoute = %v, want both dnsRouteDirect", s.dns.routeSel, connRoute(s))
	}

	// 第三条查询：与当前路由一致，不产生多余的拨号。
	if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, "www.example.org"))); err != nil {
		t.Fatalf("observeClientFrame: %v", err)
	}
	if len(router.dials) != 2 {
		t.Fatalf("dials = %d, want 2 (an unchanged route must not redial)", len(router.dials))
	}
	if s.upstream() != local1 {
		t.Fatal("a query on the current route must reuse the existing connection")
	}
	// 每条查询确实发到了当次路由的连接上：第一条走代理连接，后两条都走
	// 重绑后的直连连接（第三条复用同一条，因此不产生第三次拨号）。
	if local0.writeCount() != 1 || local1.writeCount() != 2 {
		t.Fatalf("writes per connection = %d/%d, want 1/2",
			local0.writeCount(), local1.writeCount())
	}
	// 重绑必须拆掉旧连接，否则它会一直占着一条 SOCKS5 关联直到会话结束。
	if !local0.isClosed() {
		t.Fatal("rebinding must close the previous upstream connection")
	}
	if local1.isClosed() {
		t.Fatal("the connection in use must stay open")
	}
}

// TestDNSSessionRouteUnchangedKeepsUpstream 固定"路由未变不重绑"：同一路由下的
// 连续查询复用同一条出站连接，而不是每次查询都重拨。
func TestDNSSessionRouteUnchangedKeepsUpstream(t *testing.T) {
	local0, local1 := newDNSTargetConn(), newDNSTargetConn()

	// 第二个连接只是"若发生重拨就会被取走"的探针：本用例断言它没被用到。
	router := &fakeDNSRouter{proxyDomain: "google", proxyConns: []net.Conn{local0, local1}}
	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	s.dns.router = router

	for _, domain := range []string{"mtalk.google.com", "www.google.com"} {
		if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, domain))); err != nil {
			t.Fatalf("observeClientFrame(%s): %v", domain, err)
		}
	}
	if len(router.dials) != 1 {
		t.Fatalf("dials = %d, want 1 (both queries hit the same route)", len(router.dials))
	}
	if s.upstream() != local0 {
		t.Fatal("the session must keep the first connection for an unchanged route")
	}
}

// TestDNSSessionIgnoresNonDNSDatagram 固定非 DNS 载荷不参与路由判定：端口是 53
// 但载荷不是 DNS 查询（伪造/扫描流量）时不判定路由，按直连兜底把它发出去，
// 并且不因此开启 DNS 应答学习。
func TestDNSSessionIgnoresNonDNSDatagram(t *testing.T) {
	fallback := newDNSTargetConn()
	router := &fakeDNSRouter{proxyDomain: "google", directConns: []net.Conn{fallback}}
	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	s.dns.router = router

	alive, err := s.observeClientFrame(protocol.NewFrameDATAGRAM([]byte("not a dns message")))
	if err != nil {
		t.Fatalf("observeClientFrame: %v", err)
	}
	if !alive {
		t.Fatal("a datagram frame must keep the session alive")
	}
	// 只有兜底那一次直连拨号：没有查询就没有路由判定，因此绝不会走下一级代理。
	if len(router.dials) != 1 || router.dials[0].route != dnsRouteDirect {
		t.Fatalf("dials = %+v, want exactly one direct fallback dial", router.dials)
	}
	if s.upstream() != fallback {
		t.Fatal("a non-DNS payload must go out over the direct fallback connection")
	}
	if connRoute(s) != dnsRouteDirect {
		t.Fatalf("connRoute = %v, want the direct fallback route", connRoute(s))
	}
	if s.dns.intercept {
		t.Fatal("a non-DNS payload must not arm answer interception")
	}
	if fallback.writeCount() != 1 {
		t.Fatalf("fallback writes = %d, want 1 (the datagram must still be relayed)", fallback.writeCount())
	}
}

// TestUDPRouteDialerRouteForDomain 固定生产实现的路由判定：命中 next_proxy_file
// 的域名走下一级代理，未命中的直连；enable_udp=false 时一律直连。
func TestUDPRouteDialerRouteForDomain(t *testing.T) {
	writeProxyFile := func(t *testing.T) string {
		t.Helper()
		file := t.TempDir() + "/next_proxy.txt"
		if err := os.WriteFile(file, []byte("*google*\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	newProxy := func(t *testing.T, enableUDP bool) *nextproxy.NextProxy {
		t.Helper()
		np, err := nextproxy.New("socks5://proxy.example.com:1080", enableUDP, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := np.LoadProxyFile(writeProxyFile(t)); err != nil {
			t.Fatal(err)
		}
		return np
	}

	withUDP := udpRouteDialer{nextProxy: newProxy(t, true)}
	if got := withUDP.routeForDomain("mtalk.google.com"); got != dnsRouteNextProxy {
		t.Fatalf("routeForDomain(mtalk.google.com) = %v, want the next-proxy route", got)
	}
	if got := withUDP.routeForDomain("example.com"); got != dnsRouteDirect {
		t.Fatalf("routeForDomain(example.com) = %v, want the direct route", got)
	}
	if got := withUDP.routeForDomain(""); got != dnsRouteDirect {
		t.Fatalf("routeForDomain(\"\") = %v, want the direct route", got)
	}

	// enable_udp=false：下一级代理无法承载 UDP，命中的域名也必须退回直连，
	// 否则查询会停在一个不会成功的 SOCKS5 UDP 关联上。
	noUDP := udpRouteDialer{nextProxy: newProxy(t, false)}
	if got := noUDP.routeForDomain("mtalk.google.com"); got != dnsRouteDirect {
		t.Fatalf("routeForDomain with enable_udp=false = %v, want the direct route", got)
	}
}

// TestIsDNSPort 固定触发"按域名迟拨"的判据：只有 53 端口的目标是 DNS 会话。
func TestIsDNSPort(t *testing.T) {
	tests := []struct {
		target string
		want   bool
	}{
		{"8.8.8.8:53", true},
		{"[2001:4860:4860::8888]:53", true},
		{"8.8.8.8:5353", false},
		{"1.1.1.1:853", false},
		{"8.8.8.8", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isDNSPort(tt.target); got != tt.want {
			t.Errorf("isDNSPort(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

// TestUDPHandleDefersDNSDial 固定 Handle 的分流：53 端口目标在建立会话时不出站
// （首个查询到达才拨号），非 DNS 目标维持"建立会话即按目标拨号"。
func TestUDPHandleDefersDNSDial(t *testing.T) {
	t.Run("dns target defers the dial", func(t *testing.T) {
		np, err := nextproxy.New("socks5://proxy.example.com:1080", true, false)
		if err != nil {
			t.Fatal(err)
		}
		h := newUDPHandler(30*time.Second, 30*time.Second, np)
		if h.route == nil {
			t.Fatal("a configured next proxy must provide a DNS router")
		}
		if !isDNSPort("8.8.8.8:53") {
			t.Fatal("8.8.8.8:53 must be treated as a DNS target")
		}
	})

	t.Run("unconfigured next proxy leaves the router nil", func(t *testing.T) {
		h := newUDPHandler(30*time.Second, 30*time.Second, nil)
		if h.route != nil {
			t.Fatal("without a next proxy every query must go direct (nil router)")
		}
		if h.nextProxy != nil {
			t.Fatal("nextProxy must stay nil when none is configured")
		}
	})

	t.Run("non dns target dials eagerly", func(t *testing.T) {
		conn := newDeadlineConn()
		h := newUDPHandler(30*time.Second, 30*time.Second, nil)
		h.dial.direct = func(context.Context, string, string) (net.Conn, error) { return conn, nil }

		got, remote, err := h.dial.dialTarget(context.Background(), "udp", "1.1.1.1:443")
		if err != nil {
			t.Fatal(err)
		}
		if got != conn {
			t.Fatal("a non-DNS target must be dialed before the session starts")
		}
		if remote == "" {
			t.Fatal("the dial must report a printable remote address")
		}
	})
}

// waitFor 轮询一个条件直到成立或超时。它用于等待"另一侧真的观察到了某个事实"，
// 而不是对异步进度做 sleep 猜测。
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

// testSocks5UDPUpstream 是一个最小的、支持 UDP ASSOCIATE 的 SOCKS5 服务端：
// 它只用于让"经下一级代理的 DNS 查询"走完真实的 SOCKS5 拨号，关联建立后把收到的
// 数据报原样回显（DNS 查询与应答在这里是对称的，回显足以证明查询确实从这条链路
// 出去了）。协议细节照 server/nextproxy 的测试上游实现。
type testSocks5UDPUpstream struct {
	t       *testing.T
	tcpAddr string
	mu      sync.Mutex
	seen    []string // 收到的每个数据报的目标
}

func newTestSocks5UDPUpstream(t *testing.T) *testSocks5UDPUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	u := &testSocks5UDPUpstream{t: t, tcpAddr: ln.Addr().String()}
	t.Cleanup(func() {
		_ = ln.Close()
		_ = relay.Close()
	})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go u.handle(conn, relay)
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		// ReadAddr 要求一个至少 MaxAddrLen 字节的缓冲（它按 io.Reader 读地址，
		// 传 nil 会得到 io.ErrShortBuffer）。
		addrBuf := make([]byte, socks5.MaxAddrLen)
		for {
			n, addr, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// 数据报是 RSV/FRAG/ATYP/ADDR/PORT 封装，ReadAddr 从 ATYP 开始读。
			if n < 3 {
				u.t.Errorf("upstream proxy: datagram too short (%d bytes)", n)
				continue
			}
			target, err := socks5.ReadAddr(bytes.NewReader(buf[3:n]), addrBuf)
			if err != nil {
				u.t.Errorf("upstream proxy: parse datagram destination: %v (%d bytes)", err, n)
				continue
			}
			u.mu.Lock()
			u.seen = append(u.seen, target.String())
			u.mu.Unlock()
			_, _ = relay.WriteToUDP(dnsEchoReply(u.t, buf[:n]), addr)
		}
	}()
	return u
}

// dnsEchoReply 把一条经代理收到的 DNS 查询变成一条带 A 记录的应答；载荷不是
// 可解析的 DNS 查询时原样回显。
func dnsEchoReply(t *testing.T, payload []byte) []byte {
	t.Helper()
	query := &dns.Msg{}
	if err := query.Unpack(payload); err != nil || !util.IsDNSRequest(query) {
		return payload
	}
	reply := &dns.Msg{}
	reply.SetReply(query)
	reply.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   query.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP("93.184.216.34"),
	}}
	out, err := reply.Pack()
	if err != nil {
		t.Errorf("pack reply: %v", err)
		return payload
	}
	return out
}

// proxyURL 返回喂给 nextproxy.New 的代理地址。
func (u *testSocks5UDPUpstream) proxyURL() string { return "socks5://" + u.tcpAddr }

// datagramTargets 返回代理侧收到的数据报目标，用于断言"查询确实经它转发"。
func (u *testSocks5UDPUpstream) datagramTargets() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.seen...)
}

func (u *testSocks5UDPUpstream) handle(conn net.Conn, relay *net.UDPConn) {
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, int(head[1]))); err != nil {
		return
	}
	if _, err := conn.Write([]byte{socks5.Version, socks5.MethodNoAuth}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[1] != byte(socks5.CmdUDPAssociate) {
		_, _ = conn.Write([]byte{socks5.Version, 0x07, 0, socks5.AtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	addrLen := net.IPv4len
	switch req[3] {
	case socks5.AtypIPv4:
		addrLen = net.IPv4len
	case socks5.AtypIPv6:
		addrLen = net.IPv6len
	case socks5.AtypDomainName:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		addrLen = int(lenBuf[0])
	}
	if _, err := io.ReadFull(conn, make([]byte, addrLen+2)); err != nil {
		return
	}
	relayAddr, ok := relay.LocalAddr().(*net.UDPAddr)
	if !ok {
		return
	}
	reply := []byte{socks5.Version, 0x00, 0x00, socks5.AtypIPv4}
	reply = append(reply, relayAddr.IP.To4()...)
	reply = append(reply, byte(relayAddr.Port>>8), byte(relayAddr.Port))
	if _, err := conn.Write(reply); err != nil {
		return
	}
	// 控制连接要一直开着：UDP 关联绑定在它的生命周期上。
	_, _ = io.Copy(io.Discard, conn)
}

// newClientStream 造出 Handle 需要的客户端解密读取器与 s2c 整形器，并把 s2c
// 记录流写到 sink 上。
func newClientStream(t *testing.T, body io.Reader, sink io.Writer) (*crypto.DecryptedReader, shaper.Shaper) {
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
	w, err := sk.NewWriter(sink, crypto.DirS2C, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	return dr, shaper.New(w, shaper.Config{BatchWindowMS: 1})
}

// newStreamingFrameReader 把一批**按需到达**的帧编码成客户端记录流：调用方在
// 测试过程中通过 channel 追加帧，读取侧会一直等待新帧（直到 channel 关闭）。
// 它让"会话运行到某一步之后再发下一帧"成为可能，而不必预先排好全部帧。
func newStreamingFrameReader(t *testing.T, frames <-chan protocol.Frame) io.Reader {
	t.Helper()
	sk, err := crypto.NewStreamKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 16),
		sharedconfig.EndpointUDP,
	)
	if err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	w, err := sk.NewWriter(pw, crypto.DirC2S, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer pw.Close() //nolint:errcheck
		var plain []byte
		for f := range frames {
			plain = plain[:0]
			plain = protocol.AppendFrame(plain, f)
			if err := w.WriteRecord(plain); err != nil {
				return
			}
		}
	}()
	return pr
}

// syncBuffer 是"边写边读"的同步缓冲：读取在无数据时阻塞等待写入或 Close，
// 而不是返回 EOF。会话的 s2c 推送与断言侧的读取是并发进行的，用普通的
// bytes.Buffer 会让读取在两次推送之间误判为流已结束。
type syncBuffer struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    bytes.Buffer
	closed bool
}

func newSyncBuffer() *syncBuffer {
	b := &syncBuffer{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.buf.Write(p)
	b.cond.Broadcast()
	return n, err
}

func (b *syncBuffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.buf.Len() == 0 && !b.closed {
		b.cond.Wait()
	}
	if b.buf.Len() == 0 {
		return 0, io.EOF
	}
	return b.buf.Read(p)
}

// Len 返回已写入但可能尚未被读取的字节数（只用于"确实推送过数据"这类断言）。
func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *syncBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.cond.Broadcast()
	return nil
}

// readFramesUntil 从 s2c 记录流里解出客户端方向收到的帧，直到收集到 want 条
// DATAGRAM 或超时。会话的推送与这里的读取是并发进行的，因此必须持续读取。
func readFramesUntil(t *testing.T, r io.Reader, want int, timeout time.Duration) ([][]byte, error) {
	t.Helper()
	type frameResult struct {
		frame protocol.Frame
		err   error
	}
	sk, err := crypto.NewStreamKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 16),
		sharedconfig.EndpointUDP,
	)
	if err != nil {
		t.Fatal(err)
	}
	dr, err := sk.NewReader(r, crypto.DirS2C, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan frameResult, 1)
	go func() {
		for {
			f, err := dr.ReadFrame()
			ch <- frameResult{frame: f, err: err}
			if err != nil {
				return
			}
		}
	}()

	var got [][]byte
	deadline := time.After(timeout)
	for len(got) < want {
		select {
		case res := <-ch:
			if res.err != nil {
				return got, res.err
			}
			if res.frame.Type == protocol.FrameDATAGRAM {
				got = append(got, res.frame.Payload)
			}
		case <-deadline:
			return got, fmt.Errorf("timed out waiting for %d pushed datagrams", want)
		}
	}
	return got, nil
}

// TestDNSSessionServesAnswerAfterRebind 端到端固定：一条 DNS 会话里，命中代理
// 的查询与直连的查询各自走自己的连接，重绑后从新连接读回的应答仍然会被推送给
// 客户端——路由切换不能把读取侧留在旧连接上。
//
// 用例按读取侧的真实进度推进（由 dnsPeerConn.reading 通知），不使用 sleep 或
// 轮询会话内部状态：那样既是数据竞争，也会让时序不可复现。
func TestDNSSessionServesAnswerAfterRebind(t *testing.T) {
	answer := []byte("answer-from-direct-resolver")
	proxyConn, directConn := newDNSTargetConn(), newDNSTargetConn()
	defer proxyConn.Close()  //nolint:errcheck
	defer directConn.Close() //nolint:errcheck
	directConn.reading = make(chan struct{}, 4)
	// 直连连接上先排好应答，但闸门挂在代理连接上：代理连接被关闭（即重绑完成）
	// 之后，读取侧才会从这个新连接上读到答案。
	directConn.send(answer)
	directConn.releaseAfter(proxyConn.closed)

	router := &fakeDNSRouter{proxyDomain: "google", proxyConns: []net.Conn{proxyConn}, directConns: []net.Conn{directConn}}
	frames := make(chan protocol.Frame, 4)
	frames <- protocol.NewFrameDATAGRAM(packDNSQuery(t, "mtalk.google.com"))

	pushed := newSyncBuffer()
	defer pushed.Close() //nolint:errcheck
	s, _ := newUDPSessionFixtureWithWriter(t, nil, "8.8.8.8:53", 500*time.Millisecond, nil,
		newStreamingFrameReader(t, frames), pushed)
	s.dns.router = router

	type readResult struct {
		frames [][]byte
		err    error
	}
	collected := make(chan readResult, 1)
	go func() {
		got, err := readFramesUntil(t, pushed, 1, 3*time.Second)
		collected <- readResult{frames: got, err: err}
	}()

	runDone := make(chan streamResult, 1)
	go func() { runDone <- s.run() }()

	// 第二条查询未命中代理规则：它触发重绑（并因此拆掉代理连接，放行应答）。
	frames <- protocol.NewFrameDATAGRAM(packDNSQuery(t, "example.com"))

	// 等读取侧真的切到重绑后的直连连接；这同时说明旧连接已被拆掉（应答的闸门
	// 挂在它上面），应答此刻才会被交付。
	select {
	case <-directConn.reading:
	case <-time.After(2 * time.Second):
		t.Fatal("the reader never switched to the rebound connection")
	}

	// 必须等应答真的被推给客户端之后再发 FIN：FIN 会让会话立即收尾，若它与
	// 应答同时就绪，"先取 FIN"就会把刚读到的答案一起丢掉（真实客户端也不会
	// 在一个应答到达前就拆流，因此这不是生产路径的行为）。
	select {
	case res := <-collected:
		if res.err != nil {
			t.Fatalf("read pushed frames: %v (got %d)", res.err, len(res.frames))
		}
		if len(res.frames) != 1 || !bytes.Equal(res.frames[0], answer) {
			t.Fatalf("pushed datagrams = %q, want the answer read from the rebound connection", res.frames)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the answer from the rebound connection never reached the client")
	}
	frames <- protocol.NewFrameFIN()

	select {
	case result := <-runDone:
		if result.Err != nil {
			t.Fatalf("run: %v", result.Err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the session did not finish after FIN")
	}

	if len(router.dials) != 2 {
		t.Fatalf("dials = %d, want 2 (proxy then direct)", len(router.dials))
	}
	if router.dials[0].route != dnsRouteNextProxy || router.dials[1].route != dnsRouteDirect {
		t.Fatalf("dial routes = %v/%v, want next-proxy then direct",
			router.dials[0].route, router.dials[1].route)
	}
}

// TestUDPHandlerRoutesDNSQueryThroughNextProxy 覆盖生产装配的全链路：newUDPHandler
// 造出的会话在收到命中 next_proxy_file 的 DNS 查询时，拨号真的走下一级代理
// （dialVia 收到 viaNextProxy=true 与代理域名），并且查询确实从 SOCKS5 的 UDP
// 关联转发出去——上游按真实协议观察到的数据报目标就是 DNS 目标。
//
// "应答回读并推给客户端"由 TestDNSSessionServesAnswerAfterRebind 覆盖，这条
// 用例只钉住路由与转发这一段，避免把两个关注点混在一个用例里。
func TestUDPHandlerRoutesDNSQueryThroughNextProxy(t *testing.T) {
	// 上游是一个真实完成 SOCKS5 UDP 关联的测试代理：这条用例走的是真实的
	// SOCKS5 拨号路径，只有"最终拨到哪条连接"被替换成可控连接。
	upstream := newTestSocks5UDPUpstream(t)
	np, err := nextproxy.New(upstream.proxyURL(), true, false)
	if err != nil {
		t.Fatal(err)
	}
	np.SetDialTimeout(time.Second)
	file := t.TempDir() + "/next_proxy.txt"
	if err := os.WriteFile(file, []byte("*google*\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := np.LoadProxyFile(file); err != nil {
		t.Fatal(err)
	}

	h := newUDPHandler(30*time.Second, 30*time.Second, np)
	if h.route == nil {
		t.Fatal("a configured next proxy must provide a DNS router")
	}

	// direct 分支记录被拨到的目标：DNS 查询不该落到它上面。它可能被拨号路径与
	// 读取侧并发访问，因此用互斥锁保护。
	var (
		mu          sync.Mutex
		directCalls []string
	)
	h.dial.direct = func(_ context.Context, _, target string) (net.Conn, error) {
		mu.Lock()
		directCalls = append(directCalls, target)
		mu.Unlock()
		return newDNSTargetConn(), nil
	}
	// dnsRouter 内部的 dialer 必须是同一个实例，否则上面的替换不会生效。
	rd, ok := h.route.(udpRouteDialer)
	if !ok {
		t.Fatalf("route type = %T, want udpRouteDialer", h.route)
	}
	rd.dialer = h.dial
	h.route = rd

	pushed := newSyncBuffer()
	defer pushed.Close() //nolint:errcheck
	dr, s2c := newClientStream(t, newFrameReader(t, []protocol.Frame{
		protocol.NewFrameDATAGRAM(packDNSQuery(t, "mtalk.google.com")),
		protocol.NewFrameFIN(),
	}), pushed)

	// 一边跑会话一边消费 s2c：否则应答可能让会话停在推送背压上。
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = readFramesUntil(t, pushed, 1, 2*time.Second)
	}()

	result := h.Handle(context.Background(), dr, s2c, "8.8.8.8:53", func() {})
	if result.Err != nil {
		t.Fatalf("Handle: %v", result.Err)
	}
	<-drained

	mu.Lock()
	calls := append([]string(nil), directCalls...)
	mu.Unlock()
	if len(calls) != 0 {
		t.Fatalf("direct dials = %v, want none (the query must go through the next proxy)", calls)
	}
	waitFor(t, 3*time.Second, func() bool { return len(upstream.datagramTargets()) > 0 },
		"the query never reached the upstream proxy")
	if targets := upstream.datagramTargets(); targets[0] != "8.8.8.8:53" {
		t.Fatalf("datagrams seen by the upstream proxy = %v, want one to 8.8.8.8:53", targets)
	}
}

// TestDNSSessionGarbageThenProxyQuery 是 review 指出的边界回归：首帧是 53 端口上的
// 非 DNS 载荷时会按直连兜底拨一条连接，此后第一条真实查询必须能发现"当前连接的
// 路由与它要求的不一致"并重绑到下一级代理。
//
// 判据是"查询要求的路由 vs connRoute"，而不是"与上一条查询的路由比较"：后者在
// 兜底时无人写入（兜底没有查询），会把命中代理的查询写进直连兜底连接——正是本
// PR 要修的隐私问题在这条路径上原样复现，且日志还会显示 via_next_proxy=true。
func TestDNSSessionGarbageThenProxyQuery(t *testing.T) {
	fallback, proxyConn := newDNSTargetConn(), newDNSTargetConn()
	router := &fakeDNSRouter{proxyDomain: "google", proxyConns: []net.Conn{proxyConn}, directConns: []net.Conn{fallback}}
	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	s.dns.router = router

	// 第 1 帧：非 DNS 载荷 → 直连兜底拨号（设计如此）。
	if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM([]byte("not a dns message"))); err != nil {
		t.Fatalf("observeClientFrame(garbage): %v", err)
	}
	if s.upstream() != fallback || connRoute(s) != dnsRouteDirect {
		t.Fatalf("the garbage frame must go out over the direct fallback (conn=%v route=%v)",
			s.upstream() == fallback, connRoute(s))
	}

	// 第 2 帧：命中代理规则的查询 → 必须重绑到下一级代理，而不是复用兜底连接。
	if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, "mtalk.google.com"))); err != nil {
		t.Fatalf("observeClientFrame(query): %v", err)
	}
	if len(router.dials) != 2 || router.dials[1].route != dnsRouteNextProxy {
		t.Fatalf("dials = %+v, want a direct fallback then a next-proxy dial", router.dials)
	}
	if s.upstream() != proxyConn {
		t.Fatal("the proxied query must be sent over the next-proxy connection")
	}
	if connRoute(s) != dnsRouteNextProxy {
		t.Fatalf("connRoute = %v, want dnsRouteNextProxy", connRoute(s))
	}
	// 兜底连接必须被拆掉：否则它会一直占着一条直连 socket，且查询已经不再走它。
	if !fallback.isClosed() {
		t.Fatal("rebinding must close the direct fallback connection")
	}
	if proxyConn.writeCount() != 1 {
		t.Fatalf("proxy writes = %d, want 1 (the query must go through the next proxy)", proxyConn.writeCount())
	}
}

// TestDNSSessionDialHonorsSessionContext 固定拨号使用 Handle 的请求上下文：客户端
// 断开后，一次进行中的 DNS 拨号会被取消，而不是白等到拨号超时。
func TestDNSSessionDialHonorsSessionContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	s.ctx = ctx
	s.dns.router = nil
	s.dial = dialer{direct: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return nil, ctx.Err() // 真实拨号器在 ctx 取消时会返回取消错误
	}}

	cancel()
	_, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, "mtalk.google.com")))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("observeClientFrame error = %v, want context.Canceled", err)
	}
}

// errReadConn 的 Read 返回一个**真实的非超时错误**（不是 net.ErrClosed 或超时），
// 因此会走到 targetReadError 末尾那条带远端地址的错误日志——review 指出的
// s.remote 无锁读就在那里。此前所有 fake conn 的错误都在函数前段提前返回，
// 该路径没有任何用例覆盖。
type errReadConn struct {
	closed chan struct{}
	once   sync.Once
	boom   error
}

func newErrReadConn(boom error) *errReadConn {
	return &errReadConn{closed: make(chan struct{}), boom: boom}
}

func (c *errReadConn) Read([]byte) (int, error)         { return 0, c.boom }
func (c *errReadConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *errReadConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *errReadConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *errReadConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *errReadConn) SetDeadline(time.Time) error      { return nil }
func (c *errReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *errReadConn) SetWriteDeadline(time.Time) error { return nil }

// TestDNSSessionRemoteReadPathOnRealError 覆盖 targetReadError 末尾那条真实故障
// 日志（带远端地址）：fake conn 的错误若是 net.ErrClosed 或超时会在函数前段提前
// 返回，走不到那里。这条用例保证该路径可用且远端地址通过锁读取（-race 下验证）。
func TestDNSSessionRemoteReadPathOnRealError(t *testing.T) {
	boom := errors.New("read failed")
	broken := newErrReadConn(boom)
	s, _ := newUDPSessionFixture(t, broken, "8.8.8.8:53", time.Second, nil, newBlockingConn())

	result := s.run()
	if !errors.Is(result.Err, boom) {
		t.Fatalf("run error = %v, want the target read failure", result.Err)
	}
	if !result.needsRST() {
		t.Fatal("a real target failure must ask for an RST")
	}
}
