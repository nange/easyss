package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
	socks5 "github.com/xjasonlyu/tun2socks/v2/transport/socks5"
)

// deadlineConn 把 SetReadDeadline 当作截止已到，用于断言 close 主动提前截止时间、
// 而不是等满一个空闲超时。
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

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	if !t.IsZero() && !t.After(time.Now()) {
		c.woke = true
	}
	c.mu.Unlock()
	return nil
}

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

// blockingConn 的 Read 只在 Close 后返回，让客户端帧读取真的卡在 ReadFrame 上。
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

func (c *blockingConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// 按脚本返回超限读与正常载荷：macOS 默认 net.inet.udp.maxdgram 只有 9216，
// 发不出真的 16KB UDP 数据报。
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

// 防回归：被内核截断（n == 缓冲长度）或超出预算的数据报不能转发给客户端。
func TestUDPSessionReadFromTargetDropsOversized(t *testing.T) {
	s := newUDPSession(udpSessionConfig{
		conn:        &oversizedReadConn{},
		target:      "8.8.8.8:53",
		idleTimeout: time.Second,
		ctx:         context.Background(),
	})
	go s.readFromTarget(s.upstream())
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

// newUDPSessionFixture 组装可控的 udpSession：目标是 53 端口时按 DNS 会话构造，
// 出站连接由查询域名决定，测试替换 s.dns.router 与 s.dial 即可固定路由与拨号。
func newUDPSessionFixture(t *testing.T, targetConn net.Conn, target string, idleTimeout time.Duration, np *nextproxy.NextProxy, body io.Reader) (*udpSession, *countingWriter) {
	t.Helper()
	return newUDPSessionFixtureWithWriter(t, targetConn, target, idleTimeout, np, body, nil)
}

func newUDPSessionFixtureWithWriter(t *testing.T, targetConn net.Conn, target string, idleTimeout time.Duration, np *nextproxy.NextProxy, body io.Reader, sink io.Writer) (*udpSession, *countingWriter) {
	t.Helper()

	sk, err := crypto.NewStreamKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 16),
		config.EndpointUDP,
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

	dialTimeout := config.DialTimeout(30 * time.Second)
	directDialer := outboundDialer(dialTimeout, 0)
	d := newDialer(np, func(t string) bool {
		return np != nil && np.EnableUDP() && np.ShouldProxy(t)
	}, defaultOutboundDeps())
	d.direct = func(ctx context.Context, network, target string) (net.Conn, error) {
		return d.outbound(ctx, directDialer, network, target)
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

// 防回归：会话关闭要立刻解除两处读取阻塞而不是等满空闲超时，run 也必须观察 done。
func TestUDPSessionCloseExitsReaderGoroutines(t *testing.T) {
	conn := newDeadlineConn()
	body := newBlockingConn()
	s, _ := newUDPSessionFixture(t, conn, "8.8.8.8:53", 30*time.Second, nil, body)

	runDone := make(chan streamResult, 1)
	go func() { runDone <- s.run() }()

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

// 防回归：客户端 FIN 以正常结束收尾，不触发 RST，也不等到空闲超时。
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

// 防回归：真实读错误触发 RST，拆连接错误归一化为正常结束。
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

// 防回归：DNS 应答的 A 记录与 CNAME 目标都要喂给 next proxy，
// 没见过查询的会话不得学习。
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
	s.learnFromDNS(ps)

	if !np.ShouldProxy("93.184.216.34") {
		t.Fatal("the A record from the DNS answer was not learned by the next proxy")
	}
	if !np.ShouldProxy("edge.example.net") {
		t.Fatal("the CNAME target from the DNS answer was not learned by the next proxy")
	}

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

// 防回归：非 DNS 中继流量（QUIC 等）不解析也不学习，门控被去掉时这条会失败。
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

	s.dns.intercept = true
	s.learnFromDNS(msg)
	if !np.ShouldProxy("93.184.216.34") {
		t.Fatal("an intercepted session must learn the DNS answer")
	}
}

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

func newFrameReader(t *testing.T, frames []protocol.Frame) io.Reader {
	t.Helper()
	sk, err := crypto.NewStreamKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 16),
		config.EndpointUDP,
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

type dnsDial struct {
	route  dnsRoute
	target string
	conn   net.Conn
}

// fakeDNSRouter 按域名固定路由、按顺序发放预置连接，让"哪条查询走了哪条路"可断言。
type fakeDNSRouter struct {
	proxyDomain string
	proxyConns  []net.Conn
	directConns []net.Conn
	// dials 只记成功的拨号，用于断言"这条查询走了哪条路"。
	dials []dnsDial
	// attempts 含失败的尝试，区分得出"没拨"与"拨了但失败"。
	attempts []dnsRoute
	// dialHook 在拨号真正执行前调用，把"重绑进行中"变成可观测的时序。
	dialHook func(route dnsRoute)
}

func (f *fakeDNSRouter) routeForDomain(domain string) dnsRoute {
	if strings.Contains(domain, f.proxyDomain) {
		return dnsRouteNextProxy
	}
	return dnsRouteDirect
}

func (f *fakeDNSRouter) dialRoute(_ context.Context, _, target, _ string, route dnsRoute) (net.Conn, string, error) {
	f.attempts = append(f.attempts, route)
	if f.dialHook != nil {
		f.dialHook(route)
	}
	// 与真实 dialVia 一致：直连返回对端地址，代理返回配置的下一级代理地址。
	pool, remote := &f.directConns, target
	if route.viaNextProxy() {
		pool, remote = &f.proxyConns, "127.0.0.1:4080"
	}
	if len(*pool) == 0 {
		return nil, "", fmt.Errorf("fake dns router: no more connections for route %v", route)
	}
	conn := (*pool)[0]
	*pool = (*pool)[1:]
	f.dials = append(f.dials, dnsDial{route: route, target: target, conn: conn})
	return conn, remote, nil
}

// dnsTargetConn 的读取阻塞在 recv 上，不会像 net.Pipe 那样因无人读取而卡住写入。
// after 闸门表达"旧连接拆掉后新连接才回包"，reading 通知读取侧已切到这条连接。
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

func (c *dnsTargetConn) send(payload []byte) { c.recv <- payload }

// releaseAfter 必须在连接交给会话之前调用。
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

func (c *dnsTargetConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

func connRoute(s *udpSession) dnsRoute {
	route, ok := s.upstreamRoute()
	if !ok {
		return dnsRouteDirect
	}
	return route
}

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

// 防回归：53 端口在首条查询到达前不拨号，之后按域名定路由，路由变了才重绑。
func TestDNSSessionRoutesQueryByDomain(t *testing.T) {
	local0, local1 := newDNSTargetConn(), newDNSTargetConn()

	router := &fakeDNSRouter{proxyDomain: "google", proxyConns: []net.Conn{local0}, directConns: []net.Conn{local1}}
	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	s.dns.router = router

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

	if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, "www.example.org"))); err != nil {
		t.Fatalf("observeClientFrame: %v", err)
	}
	if len(router.dials) != 2 {
		t.Fatalf("dials = %d, want 2 (an unchanged route must not redial)", len(router.dials))
	}
	if s.upstream() != local1 {
		t.Fatal("a query on the current route must reuse the existing connection")
	}
	// 每次路由变化只拨一次：重绑拨一次，upstreamOrDial 见 conn 非 nil 直接复用。
	if len(router.attempts) != 2 {
		t.Fatalf("dial attempts = %v, want exactly 2 (one per route change)", router.attempts)
	}
	if local0.writeCount() != 1 || local1.writeCount() != 2 {
		t.Fatalf("writes per connection = %d/%d, want 1/2",
			local0.writeCount(), local1.writeCount())
	}
	// 重绑不拆旧连接，它会一直占着一条 SOCKS5 关联直到会话结束。
	if !local0.isClosed() {
		t.Fatal("rebinding must close the previous upstream connection")
	}
	if local1.isClosed() {
		t.Fatal("the connection in use must stay open")
	}
}

func TestDNSSessionRouteUnchangedKeepsUpstream(t *testing.T) {
	local0, local1 := newDNSTargetConn(), newDNSTargetConn()

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

// 防回归：53 端口上的非 DNS 载荷走直连兜底，不判定路由也不开启应答学习。
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

	// enable_udp=false 时下一级代理承载不了 UDP，命中的域名也必须退回直连。
	noUDP := udpRouteDialer{nextProxy: newProxy(t, false)}
	if got := noUDP.routeForDomain("mtalk.google.com"); got != dnsRouteDirect {
		t.Fatalf("routeForDomain with enable_udp=false = %v, want the direct route", got)
	}
}

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

func TestUDPHandleDefersDNSDial(t *testing.T) {
	t.Run("dns target defers the dial", func(t *testing.T) {
		np, err := nextproxy.New("socks5://proxy.example.com:1080", true, false)
		if err != nil {
			t.Fatal(err)
		}
		h := newUDPHandler(config.Timeouts{UDPIdle: 30 * time.Second, Base: 30 * time.Second}, np, defaultOutboundDeps())
		if h.route == nil {
			t.Fatal("a configured next proxy must provide a DNS router")
		}
		if !isDNSPort("8.8.8.8:53") {
			t.Fatal("8.8.8.8:53 must be treated as a DNS target")
		}
	})

	t.Run("unconfigured next proxy leaves the router nil", func(t *testing.T) {
		h := newUDPHandler(config.Timeouts{UDPIdle: 30 * time.Second, Base: 30 * time.Second}, nil, defaultOutboundDeps())
		if h.route != nil {
			t.Fatal("without a next proxy every query must go direct (nil router)")
		}
		if h.nextProxy != nil {
			t.Fatal("nextProxy must stay nil when none is configured")
		}
	})

	t.Run("non dns target dials eagerly", func(t *testing.T) {
		conn := newDeadlineConn()
		h := newUDPHandler(config.Timeouts{UDPIdle: 30 * time.Second, Base: 30 * time.Second}, nil, defaultOutboundDeps())
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

// waitFor 等另一侧真的观察到事实，不用 sleep 猜异步进度。
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

// testSocks5UDPUpstream 支持 UDP ASSOCIATE，让 DNS 查询走完真实的 SOCKS5 拨号。
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
		// ReadAddr 要求至少 MaxAddrLen 字节的缓冲，传 nil 会得到 io.ErrShortBuffer。
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

func (u *testSocks5UDPUpstream) proxyURL() string { return "socks5://" + u.tcpAddr }

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

func newClientStream(t *testing.T, body io.Reader, sink io.Writer) (*crypto.DecryptedReader, shaper.Shaper) {
	t.Helper()
	sk, err := crypto.NewStreamKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 16),
		config.EndpointUDP,
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

// newStreamingFrameReader 的帧按需到达，测试可以先跑会话到某一步再发下一帧。
func newStreamingFrameReader(t *testing.T, frames <-chan protocol.Frame) io.Reader {
	t.Helper()
	sk, err := crypto.NewStreamKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 16),
		config.EndpointUDP,
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

// syncBuffer 无数据时阻塞而不是返回 EOF，否则两次推送之间会被误判为流已结束。
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

func readFramesUntil(t *testing.T, r io.Reader, want int, timeout time.Duration) ([][]byte, error) {
	t.Helper()
	type frameResult struct {
		frame protocol.Frame
		err   error
	}
	sk, err := crypto.NewStreamKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 16),
		config.EndpointUDP,
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

// 防回归：重绑后从新连接读回的应答仍要推给客户端，读取侧不能留在旧连接上。
func TestDNSSessionServesAnswerAfterRebind(t *testing.T) {
	answer := []byte("answer-from-direct-resolver")
	proxyConn, directConn := newDNSTargetConn(), newDNSTargetConn()
	defer proxyConn.Close()  //nolint:errcheck
	defer directConn.Close() //nolint:errcheck
	directConn.reading = make(chan struct{}, 4)
	// 应答的闸门挂在代理连接上：它被关闭（重绑完成）后读取侧才读到答案。
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

	frames <- protocol.NewFrameDATAGRAM(packDNSQuery(t, "example.com"))

	select {
	case <-directConn.reading:
	case <-time.After(2 * time.Second):
		t.Fatal("the reader never switched to the rebound connection")
	}

	// 等应答推给客户端后再发 FIN：两者同时就绪时先取 FIN 会把答案一起丢掉。
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

// 防回归：DNS 查询经真实的 SOCKS5 UDP 关联转发，上游看到的数据报目标就是解析器。
func TestUDPHandlerRoutesDNSQueryThroughNextProxy(t *testing.T) {
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

	h := newUDPHandler(config.Timeouts{UDPIdle: 30 * time.Second, Base: 30 * time.Second}, np, defaultOutboundDeps())
	if h.route == nil {
		t.Fatal("a configured next proxy must provide a DNS router")
	}

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
	// dnsRouter 内部的 dialer 必须是同一个实例，否则上面的替换不生效。
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

	// 一边跑会话一边消费 s2c，否则应答会让会话卡在推送背压上。
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

// 防回归：首帧是非 DNS 载荷留下的直连兜底连接，必须被第一条真实查询发现并重绑。
// 判据是"查询要求的路由 vs connRoute"：与上一条查询比较时兜底那帧无人写入，会漏掉它。
func TestDNSSessionGarbageThenProxyQuery(t *testing.T) {
	fallback, proxyConn := newDNSTargetConn(), newDNSTargetConn()
	router := &fakeDNSRouter{proxyDomain: "google", proxyConns: []net.Conn{proxyConn}, directConns: []net.Conn{fallback}}
	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	s.dns.router = router

	if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM([]byte("not a dns message"))); err != nil {
		t.Fatalf("observeClientFrame(garbage): %v", err)
	}
	if s.upstream() != fallback || connRoute(s) != dnsRouteDirect {
		t.Fatalf("the garbage frame must go out over the direct fallback (conn=%v route=%v)",
			s.upstream() == fallback, connRoute(s))
	}

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
	if !fallback.isClosed() {
		t.Fatal("rebinding must close the direct fallback connection")
	}
	if proxyConn.writeCount() != 1 {
		t.Fatalf("proxy writes = %d, want 1 (the query must go through the next proxy)", proxyConn.writeCount())
	}
}

// 防回归：重绑拨号失败要保留旧连接与旧路由，同一帧只拨一次。
func TestDNSSessionRebindDialFailureKeepsUpstream(t *testing.T) {
	fallback := newDNSTargetConn()
	router := &fakeDNSRouter{proxyDomain: "google", directConns: []net.Conn{fallback}}
	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	s.dns.router = router

	if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM([]byte("not a dns message"))); err != nil {
		t.Fatalf("observeClientFrame(garbage): %v", err)
	}
	if s.upstream() != fallback || connRoute(s) != dnsRouteDirect {
		t.Fatalf("the garbage frame must establish the direct fallback (conn=%v route=%v)",
			s.upstream() == fallback, connRoute(s))
	}

	alive, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, "mtalk.google.com")))
	if err != nil {
		t.Fatalf("observeClientFrame must survive a failed rebind: %v", err)
	}
	if !alive {
		t.Fatal("a failed rebind must not end the session")
	}
	if got := router.attempts; len(got) != 2 {
		t.Fatalf("dial attempts = %v, want exactly 2 (fallback + one rebind attempt)", got)
	}
	if s.upstream() != fallback {
		t.Fatal("a failed rebind must keep the old upstream connection")
	}
	if !fallback.isOpen() {
		t.Fatal("a failed rebind must not close the old upstream connection")
	}
	if connRoute(s) != dnsRouteDirect {
		t.Fatalf("connRoute = %v, want the old direct route to be preserved", connRoute(s))
	}
	if fallback.writeCount() != 2 {
		t.Fatalf("fallback writes = %d, want 2 (the failed-to-rebind query must still go out)",
			fallback.writeCount())
	}
	if s.dns.routeSel != dnsRouteNextProxy {
		t.Fatalf("routeSel = %v, want the query's requested route to be recorded", s.dns.routeSel)
	}

	// 冷却窗口内不重拨，否则下一级代理长时间不可用时每个查询都同步吃满一次 DialTimeout。
	alive, err = s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, "mtalk.google.com")))
	if err != nil {
		t.Fatalf("observeClientFrame(retry): %v", err)
	}
	if !alive {
		t.Fatal("a retried query must keep the session alive")
	}
	if got := router.attempts; len(got) != 2 {
		t.Fatalf("dial attempts = %v, want exactly 2 (the retry must be suppressed by the cooldown)", got)
	}
	if s.upstream() != fallback || connRoute(s) != dnsRouteDirect {
		t.Fatalf("the retry must keep using the old connection/route (conn=%v route=%v)",
			s.upstream() == fallback, connRoute(s))
	}
	if fallback.writeCount() != 3 {
		t.Fatalf("fallback writes = %d, want 3", fallback.writeCount())
	}

	s.dns.rebindFailedAt = time.Now().Add(-rebindCooldown - time.Second)
	if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, "mtalk.google.com"))); err != nil {
		t.Fatalf("observeClientFrame(after cooldown): %v", err)
	}
	if got := router.attempts; len(got) != 3 {
		t.Fatalf("dial attempts = %v, want 3 after the cooldown expired", got)
	}
}

// 防回归：重绑期间在 frameCh 排队的查询要写到新连接，不写旧连接，也不额外重拨。
func TestDNSSessionQueryDuringRebindUsesNewRoute(t *testing.T) {
	fallback, proxyConn := newDNSTargetConn(), newDNSTargetConn()
	router := &fakeDNSRouter{proxyDomain: "google", proxyConns: []net.Conn{proxyConn}, directConns: []net.Conn{fallback}}

	entered := make(chan struct{})
	release := make(chan struct{})
	router.dialHook = func(route dnsRoute) {
		if route != dnsRouteNextProxy {
			return
		}
		select {
		case <-entered:
			return
		default:
		}
		close(entered)
		<-release
	}

	frames := make(chan protocol.Frame, 4)
	frames <- protocol.NewFrameDATAGRAM([]byte("not a dns message"))
	frames <- protocol.NewFrameDATAGRAM(packDNSQuery(t, "mtalk.google.com"))
	frames <- protocol.NewFrameDATAGRAM(packDNSQuery(t, "www.google.com"))

	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", 5*time.Second, nil,
		newStreamingFrameReader(t, frames))
	s.dns.router = router

	runDone := make(chan streamResult, 1)
	runStopped := make(chan struct{})
	go func() {
		defer close(runStopped)
		runDone <- s.run()
	}()
	// 断言失败时也要拆会话，否则 run goroutine 与两个 reader 会一直挂着。
	t.Cleanup(func() {
		s.close()
		select {
		case <-runStopped:
		case <-time.After(2 * time.Second):
			t.Error("run did not return during cleanup")
		}
	})

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the rebind dial was never entered")
	}

	if s.upstream() != fallback || !fallback.isOpen() {
		t.Fatal("the old connection must stay installed while the new one is dialing")
	}

	close(release)

	waitFor(t, 2*time.Second, func() bool { return proxyConn.writeCount() == 2 },
		"both queued queries must be written to the rebind connection")
	if got := router.attempts; len(got) != 2 {
		t.Fatalf("dial attempts = %v, want exactly 2 (fallback + one rebind)", got)
	}
	if s.upstream() != proxyConn {
		t.Fatal("the successful rebind must install the new connection")
	}
	if !fallback.isClosed() {
		t.Fatal("the successful rebind must close the old connection")
	}
	if connRoute(s) != dnsRouteNextProxy {
		t.Fatalf("connRoute = %v, want dnsRouteNextProxy", connRoute(s))
	}
	if fallback.writeCount() != 1 {
		t.Fatalf("fallback writes = %d, want 1", fallback.writeCount())
	}

	s.close()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after close")
	}
	select {
	case <-runStopped:
	case <-time.After(2 * time.Second):
		t.Fatal("run goroutine did not finish")
	}
}

// 防回归：重绑失败后 via_next_proxy 必须描述实际写出的旧连接，并带 route_pending=true。
// 必须串行：它替换进程级 logger，与同包并行测试同时运行会互相吞掉日志。
func TestDNSSessionRebindFailureLogsActualPath(t *testing.T) {
	fallback := newDNSTargetConn()
	router := &fakeDNSRouter{proxyDomain: "google", directConns: []net.Conn{fallback}}
	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	s.dns.router = router

	rec := &recordingHandler{}
	prev := log.Logger()
	log.SetLogger(slog.New(rec))
	t.Cleanup(func() { log.SetLogger(prev) })

	if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM([]byte("not a dns message"))); err != nil {
		t.Fatalf("observeClientFrame(garbage): %v", err)
	}
	if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, "mtalk.google.com"))); err != nil {
		t.Fatalf("observeClientFrame(query): %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	var found bool
	for _, r := range rec.records {
		if !strings.HasPrefix(r.Message, "[UDP_DNS]") {
			continue
		}
		attrs := attrsOf(r)
		if attrs["domain"] != "mtalk.google.com" {
			continue
		}
		found = true
		if attrs["via_next_proxy"] != "false" {
			t.Fatalf("via_next_proxy = %q, want false (the query actually used the old direct connection)",
				attrs["via_next_proxy"])
		}
		if attrs["route_pending"] != "true" {
			t.Fatalf("route_pending = %q, want true after a failed rebind", attrs["route_pending"])
		}
	}
	if !found {
		t.Fatal("no [UDP_DNS] record for the query")
	}
}

func TestDNSSessionDialHonorsSessionContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	s.ctx = ctx
	s.dns.router = nil
	s.dial = newDialer(nil, nil, defaultOutboundDeps())
	s.dial.direct = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return nil, ctx.Err() // 真实拨号器在 ctx 取消时会返回取消错误
	}

	cancel()
	_, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, "mtalk.google.com")))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("observeClientFrame error = %v, want context.Canceled", err)
	}
}

// errReadConn 返回真实的非超时错误，才会走到 targetReadError 原样返回的分支。
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

// 防回归：真实读错误不能被归一化成 io.EOF，要作为会话失败返回。
func TestDNSSessionTargetReadErrorReturnsFailure(t *testing.T) {
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

// 防回归：错误结果必须带回产生它的连接，run 才能丢弃已退役连接的错误。
func TestUDPTargetReadErrorCarriesSource(t *testing.T) {
	boom := errors.New("read failed")
	broken := newErrReadConn(boom)
	s, _ := newUDPSessionFixture(t, broken, "8.8.8.8:53", time.Second, nil, newBlockingConn())

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.readFromTarget(broken)
	}()

	select {
	case res := <-s.resultCh:
		if res.conn != broken {
			t.Fatalf("result source = %v, want the broken target connection", res.conn)
		}
		if !errors.Is(res.err, boom) {
			t.Fatalf("result error = %v, want %v", res.err, boom)
		}
	case <-time.After(time.Second):
		t.Fatal("readFromTarget did not report the error")
	}
	<-done
	s.close()
}

// 防回归：读取侧快照之后主 goroutine 可能完成重绑，旧连接的错误不得结束新连接健康的会话。
func TestUDPSessionIgnoresRetiredConnReadError(t *testing.T) {
	current := newDNSTargetConn()
	s, _ := newUDPSessionFixture(t, current, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	retired := newDNSTargetConn()
	s.resultCh <- udpDatagram{conn: retired, err: errors.New("retired read failed")}

	done := make(chan streamResult, 1)
	go func() { done <- s.run() }()

	select {
	case res := <-done:
		t.Fatalf("a retired connection error ended the session: %v", res.Err)
	case <-time.After(100 * time.Millisecond):
	}

	s.close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after close")
	}
}

// infoRecordsWith 返回消息以 prefix 开头的 Info 记录，供级别与字段断言使用。
func infoRecordsWith(rec *recordingHandler, prefix string) []slog.Record {
	var out []slog.Record
	for _, r := range rec.at(slog.LevelInfo) {
		if strings.HasPrefix(r.Message, prefix) {
			out = append(out, r)
		}
	}
	return out
}

// 防回归：代理路径的 remote 是下一级代理地址，与直连的对端地址必须分字段，DNS 会话另带
// domain，否则一条"目标 8.8.8.8:53、remote 127.0.0.1:4080"的日志无从解释。
// 必须串行：它替换进程级 logger，与同包并行测试同时运行会互相吞掉日志。
func TestUDPUpstreamConnectedLogFields(t *testing.T) {
	rec := &recordingHandler{}
	prev := log.Logger()
	log.SetLogger(slog.New(rec))
	t.Cleanup(func() { log.SetLogger(prev) })

	router := &fakeDNSRouter{
		proxyDomain: "google",
		proxyConns:  []net.Conn{newDNSTargetConn()},
		directConns: []net.Conn{newDNSTargetConn()},
	}
	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	s.dns.router = router
	t.Cleanup(s.close)

	for _, domain := range []string{"mtalk.google.com", "api.github.com"} {
		if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, domain))); err != nil {
			t.Fatalf("observeClientFrame(%s): %v", domain, err)
		}
	}

	records := infoRecordsWith(rec, "[UDP] upstream connected")
	if len(records) != 2 {
		t.Fatalf("[UDP] upstream connected records = %d, want 2", len(records))
	}

	proxied := attrsOf(records[0])
	if proxied["domain"] != "mtalk.google.com" || proxied["via_next_proxy"] != "true" {
		t.Fatalf("proxied attrs = %v", proxied)
	}
	if proxied["proxy"] != "127.0.0.1:4080" {
		t.Fatalf("proxy = %q, want the configured next proxy", proxied["proxy"])
	}
	if _, ok := proxied["remote"]; ok {
		t.Fatalf("the proxied record must not carry a socket remote: %v", proxied)
	}

	direct := attrsOf(records[1])
	if direct["domain"] != "api.github.com" || direct["via_next_proxy"] != "false" {
		t.Fatalf("direct attrs = %v", direct)
	}
	if direct["remote"] != "8.8.8.8:53" {
		t.Fatalf("remote = %q, want the resolver peer", direct["remote"])
	}
	if _, ok := direct["proxy"]; ok {
		t.Fatalf("the direct record must not carry a proxy: %v", direct)
	}
}

// 防回归：首条查询命中代理时 [UDP_DNS] 必须是 Info——拨号失败不会有 [UDP] upstream
// connected 说明原因；同一会话后续同路由查询留在 Debug，不随查询数增长。
// 必须串行：它替换进程级 logger，与同包并行测试同时运行会互相吞掉日志。
func TestDNSSessionFirstProxiedQueryLogsInfoOnce(t *testing.T) {
	rec := &recordingHandler{}
	prev := log.Logger()
	log.SetLogger(slog.New(rec))
	t.Cleanup(func() { log.SetLogger(prev) })

	router := &fakeDNSRouter{
		proxyDomain: "google",
		proxyConns:  []net.Conn{newDNSTargetConn(), newDNSTargetConn()},
		directConns: []net.Conn{newDNSTargetConn()},
	}
	s, _ := newUDPSessionFixture(t, nil, "8.8.8.8:53", time.Second, nil, newBlockingConn())
	s.dns.router = router
	t.Cleanup(s.close)

	for _, domain := range []string{"mtalk.google.com", "www.google.com"} {
		if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, domain))); err != nil {
			t.Fatalf("observeClientFrame(%s): %v", domain, err)
		}
	}

	records := infoRecordsWith(rec, "[UDP_DNS]")
	if len(records) != 1 {
		t.Fatalf("[UDP_DNS] Info records = %d, want 1 (only the first query of a session)", len(records))
	}
	first := attrsOf(records[0])
	if first["domain"] != "mtalk.google.com" || first["via_next_proxy"] != "true" {
		t.Fatalf("first query attrs = %v", first)
	}
	if _, ok := first["route_changed"]; ok {
		t.Fatalf("the first query must not claim route_changed: %v", first)
	}

	// 直连查询会触发重绑，route_changed 的 Info 不能被首查规则吞掉。
	if _, err := s.observeClientFrame(protocol.NewFrameDATAGRAM(packDNSQuery(t, "api.github.com"))); err != nil {
		t.Fatalf("observeClientFrame(api.github.com): %v", err)
	}
	records = infoRecordsWith(rec, "[UDP_DNS]")
	if len(records) != 2 {
		t.Fatalf("[UDP_DNS] Info records = %d, want 2 after a route change", len(records))
	}
	changed := attrsOf(records[1])
	if changed["route_changed"] != "true" || changed["via_next_proxy"] != "false" {
		t.Fatalf("route change attrs = %v", changed)
	}
}
