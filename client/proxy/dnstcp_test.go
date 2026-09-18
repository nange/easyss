package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	clientconfig "github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/transport"
	"github.com/txthinking/socks5"
)

// testMasterKey 必须与 newTestStreamHandler 中使用的会话主密钥一致，测试才能
// 在服务端侧解密客户端写出的引导记录。
var testMasterKey = func() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}()

// newTCPDNSTestServer 构造一个用于 TCP DNS 拦截测试的 Socks5Server。
func newTCPDNSTestServer(t *testing.T, rt *router.Router, tr transport.Transport) *Socks5Server {
	t.Helper()
	h := newTestStreamHandler(tr)
	srv, err := NewSocks5Server(Socks5Options{
		ListenAddr: "127.0.0.1:0",
		Handler:    h,
		Router:     rt,
		Method:     protocol.MethodAES256GCM,
		Timeouts: sharedconfig.Timeouts{
			Base:       30 * time.Second,
			Dial:       10 * time.Second,
			StreamIdle: 30 * time.Second,
			DNSResp:    5 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	return srv
}

// serveTCPDNSHandler 起一个 TCP 对，服务端把连接交给 handleTCPDNS，返回客户端
// 连接及其带缓冲的读取器。清理时先关客户端连接，再等处理 goroutine 结束。
func serveTCPDNSHandler(t *testing.T, srv *Socks5Server, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen handler conn: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		host, _, _ := net.SplitHostPort(target)
		_ = srv.handleTCPDNS(conn, &socks5.Request{}, target, host)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial handler conn: %v", err)
	}
	t.Cleanup(func() { <-done })
	t.Cleanup(func() { client.Close() }) //nolint:errcheck
	t.Cleanup(func() { ln.Close() })     //nolint:errcheck
	return client, bufio.NewReader(client)
}

// fakeEncryptedUpstream 让 mockTransport 产出的流"会应答"：它在服务端侧扮演
// 加密会话的远端，读出客户端写来的引导记录（含 DNS 查询），再用同一套密钥在
// s2c 方向写回一条 DATAGRAM 应答。这样代理 DNS 的成功路径（而不只是上游沉默的
// 失败路径）可以在没有真实传输层的情况下被端到端验证。
type fakeEncryptedUpstream struct {
	mu         sync.Mutex
	written    []byte // c2s：客户端写入的字节
	resp       []byte // s2c：测试回写的应答记录
	separating bool   // serve 开始回写应答后置位，后续 Write 落入 resp
	dataReady  chan struct{}
	readyOnce  sync.Once
	closed     chan struct{}
	closeOnce  sync.Once
}

func newFakeEncryptedUpstream() *fakeEncryptedUpstream {
	return &fakeEncryptedUpstream{
		dataReady: make(chan struct{}),
		closed:    make(chan struct{}),
	}
}

// writtenLen 返回客户端已写入 c2s 方向的字节数（用于等待引导记录落盘）。
func (f *fakeEncryptedUpstream) writtenLen() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.written)
}

func (f *fakeEncryptedUpstream) markDataReady() {
	f.readyOnce.Do(func() { close(f.dataReady) })
}

// separate 让 serve 之后的写入进入 s2c 缓冲区。必须在写入应答之前调用。
func (f *fakeEncryptedUpstream) separate() {
	f.mu.Lock()
	f.separating = true
	f.mu.Unlock()
}

// Read 只交出 s2c 方向的应答字节（c2s 的引导记录由 ReadFirstRecord 从 written
// 单独读取）。没有数据时必须阻塞——返回 (0, nil) 会让 io.ReadFull 空转。
func (f *fakeEncryptedUpstream) Read(p []byte) (int, error) {
	f.mu.Lock()
	if len(f.resp) > 0 {
		n := copy(p, f.resp)
		f.resp = f.resp[n:]
		f.mu.Unlock()
		return n, nil
	}
	f.mu.Unlock()

	select {
	case <-f.dataReady:
		return f.Read(p)
	case <-f.closed:
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.resp) > 0 {
			n := copy(p, f.resp)
			f.resp = f.resp[n:]
			return n, nil
		}
		return 0, io.EOF
	}
}

func (f *fakeEncryptedUpstream) Write(p []byte) (int, error) {
	f.mu.Lock()
	if f.separating {
		f.resp = append(f.resp, p...)
	} else {
		f.written = append(f.written, p...)
	}
	f.mu.Unlock()
	f.markDataReady()
	return len(p), nil
}

func (f *fakeEncryptedUpstream) CloseWrite() error { return nil }
func (f *fakeEncryptedUpstream) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

// serve 读取客户端写来的引导记录（含 DNS 查询），再用同一套密钥在 s2c 方向
// 加密回写一条 DATAGRAM 应答。responder 返回 nil 表示故意沉默，交由调用方的
// dnsRespTimeout 处理。
func (f *fakeEncryptedUpstream) serve(salt []byte, masterKey []byte, responder func(*dns.Msg) *dns.Msg) error {
	// 客户端在引导记录写出之前不会去读应答（Receive 紧随 Open 之后），因此这里
	// 必须等到引导记录（含 DNS 查询）真正落盘，否则应答会先于引导记录被读走。
	deadline := time.Now().Add(3 * time.Second)
	for f.writtenLen() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	f.mu.Lock()
	bootstrap := append([]byte(nil), f.written...)
	f.mu.Unlock()
	if len(bootstrap) == 0 {
		return errors.New("bootstrap record never arrived")
	}

	sk, err := crypto.NewStreamKeys(masterKey, salt, sharedconfig.EndpointUDP)
	if err != nil {
		return err
	}
	fr, err := sk.ReadFirstRecord(bytes.NewReader(bootstrap))
	if err != nil {
		return err
	}
	var query *dns.Msg
	for _, frame := range fr.Leftover {
		if frame.Type != protocol.FrameDATAGRAM {
			continue
		}
		query = new(dns.Msg)
		if err := query.Unpack(frame.Payload); err != nil {
			return err
		}
		break
	}
	if query == nil {
		return errors.New("bootstrap carried no DNS query")
	}
	reply := responder(query)
	if reply == nil {
		return nil
	}
	data, err := reply.Pack()
	if err != nil {
		return err
	}
	plaintext := protocol.EncodeFrames([]protocol.Frame{protocol.NewFrameDATAGRAM(data)})

	f.separate()
	sw, err := sk.NewWriter(f, crypto.DirS2C, protocol.MethodAES256GCM)
	if err != nil {
		return err
	}
	if err := sw.WriteRecord(plaintext); err != nil {
		return err
	}
	sw.Flush()
	f.markDataReady()
	return nil
}

// readSocks5Reply 读取并丢弃一条 SOCKS5 CONNECT 应答。
func readSocks5Reply(t *testing.T, r *bufio.Reader) {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("read socks5 reply header: %v", err)
	}
	if hdr[0] != 0x05 {
		t.Fatalf("socks5 version = %d, want 5", hdr[0])
	}
	if hdr[1] != 0x00 {
		t.Fatalf("socks5 reply code = %d, want 0", hdr[1])
	}
	var addrLen int
	switch hdr[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			t.Fatalf("read domain length: %v", err)
		}
		addrLen = int(l[0])
	default:
		t.Fatalf("unknown atyp %d in socks5 reply", hdr[3])
	}
	if _, err := io.ReadFull(r, make([]byte, addrLen+2)); err != nil {
		t.Fatalf("read socks5 reply address: %v", err)
	}
}

// startUDPDNSResponder 启动一个本地 UDP DNS 应答器：任意 A 查询回 answerIP。
func startUDPDNSResponder(t *testing.T, answerIP string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp responder: %v", err)
	}
	t.Cleanup(func() { pc.Close() }) //nolint:errcheck
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(answerIP),
			})
			data, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(data, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestTCPDNSMessageFraming(t *testing.T) {
	// round-trip：写入的帧能被 readTCPDNSMessage 原样读出。
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() }) //nolint:errcheck
	t.Cleanup(func() { server.Close() }) //nolint:errcheck

	go func() {
		q := new(dns.Msg)
		q.SetQuestion("framing.example.com.", dns.TypeA)
		if err := writeTCPDNSMessage(server, q); err != nil {
			t.Errorf("write: %v", err)
		}
	}()

	server.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	msg, err := readTCPDNSMessage(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read round-trip: %v", err)
	}
	if len(msg.Question) != 1 || msg.Question[0].Name != "framing.example.com." {
		t.Errorf("question = %v, want framing.example.com.", msg.Question)
	}

	// 零长度：拒绝。
	if _, err := readTCPDNSMessage(bufio.NewReader(&bytesReader{data: []byte{0, 0}}), nil); err == nil {
		t.Error("zero-length message accepted, want error")
	}
	// 超长：拒绝。
	if _, err := readTCPDNSMessage(bufio.NewReader(&bytesReader{data: []byte{0xff, 0xff}}), nil); err == nil {
		t.Error("oversized length accepted, want error")
	}
}

// bytesReader 是 io.Reader 的极简实现，避免为两字节测试创建文件。
type bytesReader struct {
	data []byte
}

func (b *bytesReader) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

func TestHandleTCPDNSDirect(t *testing.T) {
	easydns.ResetResolveState()
	requested := startUDPDNSResponder(t, "1.2.3.4")
	// 内置列表故意指向一个必然拨不通的地址：只有真正使用客户端请求的解析器
	// （requested），这个用例才会拿到应答；若代码忽略请求地址而转投内置列表，
	// 这里就会变成 SERVFAIL。
	oldDNS := clientconfig.DirectDNSServers
	clientconfig.DirectDNSServers = []string{"127.0.0.1:1"}
	t.Cleanup(func() { clientconfig.DirectDNSServers = oldDNS })

	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	rt.AddDirectDomain("direct.example.com")

	srv := newTCPDNSTestServer(t, rt, &mockTransport{})
	client, br := serveTCPDNSHandler(t, srv, requested)

	q := new(dns.Msg)
	q.SetQuestion("direct.example.com.", dns.TypeA)
	q.Id = 0x1234
	if err := writeTCPDNSMessage(client, q); err != nil {
		t.Fatalf("write query: %v", err)
	}

	readSocks5Reply(t, br)
	resp, err := readTCPDNSMessage(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Id != 0x1234 {
		t.Errorf("response id = %#x, want %#x", resp.Id, 0x1234)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR (requested resolver must be dialed)", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", resp.Answer[0])
	}
	if a.A.String() != "1.2.3.4" {
		t.Errorf("answer = %s, want 1.2.3.4", a.A.String())
	}

	// 结果应写入直连缓存。
	if cached := srv.dnsCache.Get("direct.example.com.", "A", true); cached == nil {
		t.Error("direct answer not cached")
	}
}

// TestHandleTCPDNSDirectFallsBackToBuiltinList 覆盖另一侧：客户端请求的解析器
// 不可拨号（这里用未指定地址）时，直连分支必须回落到内置列表，而不是直接把
// 查询打成 SERVFAIL。
func TestHandleTCPDNSDirectFallsBackToBuiltinList(t *testing.T) {
	easydns.ResetResolveState()
	oldDNS := clientconfig.DirectDNSServers
	clientconfig.DirectDNSServers = []string{startUDPDNSResponder(t, "5.6.7.8")}
	t.Cleanup(func() { clientconfig.DirectDNSServers = oldDNS })

	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	rt.AddDirectDomain("direct.example.com")

	srv := newTCPDNSTestServer(t, rt, &mockTransport{})
	client, br := serveTCPDNSHandler(t, srv, "0.0.0.0:53")

	q := new(dns.Msg)
	q.SetQuestion("direct.example.com.", dns.TypeA)
	if err := writeTCPDNSMessage(client, q); err != nil {
		t.Fatalf("write query: %v", err)
	}

	readSocks5Reply(t, br)
	resp, err := readTCPDNSMessage(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1 (builtin list fallback)", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "5.6.7.8" {
		t.Fatalf("answer = %v, want 5.6.7.8", resp.Answer[0])
	}
}

func TestHandleTCPDNSBlock(t *testing.T) {
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAutoBlock, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	srv := newTCPDNSTestServer(t, rt, &mockTransport{})
	client, br := serveTCPDNSHandler(t, srv, "223.5.5.5:53")

	q := new(dns.Msg)
	q.SetQuestion("adsensecamp.com.", dns.TypeA)
	q.Id = 0x1111
	if err := writeTCPDNSMessage(client, q); err != nil {
		t.Fatalf("write query: %v", err)
	}

	readSocks5Reply(t, br)
	resp, err := readTCPDNSMessage(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Id != 0x1111 {
		t.Errorf("response id = %#x, want %#x", resp.Id, 0x1111)
	}
	// 屏蔽语义与 UDP 路径保持一致：NOERROR + 空答案（而不是 REFUSED），
	// 否则部分 stub resolver 会绕过负缓存反复重试同一域名。
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("answers = %d, want 0", len(resp.Answer))
	}
	if !resp.Response {
		t.Error("blocked reply must have the response bit set")
	}
}

// upstreamTransport 记录最近一次 Open 请求里的 salt，使测试能构造出与服务端
// 完全一致的加密密钥；应答流由调用方通过 customStream 提供。
type upstreamTransport struct {
	*mockTransport
	mu   sync.Mutex
	salt []byte
}

func (u *upstreamTransport) Open(ctx context.Context, req transport.OpenRequest) (transport.Stream, error) {
	raw, err := base64.RawURLEncoding.DecodeString(req.Salt)
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	u.salt = raw
	u.mu.Unlock()
	return u.mockTransport.Open(ctx, req)
}

func (u *upstreamTransport) saltOf() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.salt
}

// newTCPDNSProxyServer 构造一个测试服务器：传输层由调用方给定的流承载，直连
// 拨号被替换成一个必定失败的桩（代理分支本就不该拨直连）。返回的 transport 在
// 收到 Open 后即可取到 salt。
func newTCPDNSProxyServer(t *testing.T, rt *router.Router, stream transport.Stream) (*Socks5Server, *upstreamTransport) {
	t.Helper()
	tr := &upstreamTransport{mockTransport: &mockTransport{streams: []transport.Stream{stream}}}
	srv := newTCPDNSTestServer(t, rt, tr)
	if srv.directDialContext == nil {
		t.Fatal("directDialContext must be set by the constructor")
	}
	srv.directDialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("direct dial must not be used on the proxy path")
	}
	return srv, tr
}

// TestHandleTCPDNSProxySuccess 覆盖代理分支的成功路径：查询经隧道发出，上游
// 返回的应答必须被原样解出、写回客户端并写入代理缓存（既有用例只覆盖了上游
// 沉默 → SERVFAIL 的失败路径）。
func TestHandleTCPDNSProxySuccess(t *testing.T) {
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	rt.AddProxyDomain("proxy.example.com")

	stream := newFakeEncryptedUpstream()
	srv, tr := newTCPDNSProxyServer(t, rt, stream)
	client, br := serveTCPDNSHandler(t, srv, "8.8.8.8:53")

	serveErr := make(chan error, 1)
	go func() {
		// salt 要等 Open 被调用后才有值，这里让它先就绪。
		for i := 0; i < 200 && tr.saltOf() == nil; i++ {
			time.Sleep(5 * time.Millisecond)
		}
		salt := tr.saltOf()
		if salt == nil {
			serveErr <- errors.New("transport never opened a stream")
			return
		}
		serveErr <- stream.serve(salt, testMasterKey, func(q *dns.Msg) *dns.Msg {
			resp := new(dns.Msg)
			resp.SetReply(q)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("9.9.9.9"),
			})
			return resp
		})
	}()

	q := new(dns.Msg)
	q.SetQuestion("proxy.example.com.", dns.TypeA)
	q.Id = 0x3333
	if err := writeTCPDNSMessage(client, q); err != nil {
		t.Fatalf("write query: %v", err)
	}

	readSocks5Reply(t, br)
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("fake upstream: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fake upstream never served the query")
	}
	resp, err := readTCPDNSMessage(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Id != 0x3333 || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("response id = %#x rcode = %d, want id 0x3333 NOERROR", resp.Id, resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "9.9.9.9" {
		t.Fatalf("answer = %v, want 9.9.9.9", resp.Answer[0])
	}
	if cached := srv.dnsCache.Get("proxy.example.com.", "A", false); cached == nil {
		t.Error("proxied answer not cached")
	}
}

// TestHandleTCPDNSFallbackNonDNSDirectCrossPath 覆盖回退的另一半：首条报文不是
// DNS 查询时，连接必须被完整交回 routeTCP（写回 SOCKS5 成功应答并按规则分流），
// 而不是留下一个从未应答的 SOCKS5 连接。这里用自定义直连域名 + 本地 TCP 目标，
// 使回退路径与既有 TestHandleTCPDNSFallbackNonDNS 走的分支不同。
func TestHandleTCPDNSFallbackNonDNSDirectCrossPath(t *testing.T) {
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	rt.AddDirectDomain("direct.example.com")

	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { upstreamLn.Close() }) //nolint:errcheck
	got := make(chan string, 1)
	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		buf := make([]byte, 32)
		n, _ := conn.Read(buf)
		got <- string(buf[:n])
	}()

	srv := newTCPDNSTestServer(t, rt, &mockTransport{})
	srv.directDialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, upstreamLn.Addr().String())
	}
	client, br := serveTCPDNSHandler(t, srv, "direct.example.com:53")

	// "hello" 的前两字节被当作长度字段后读不满 → 首条报文解析失败 → 回退中继。
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write non-dns bytes: %v", err)
	}
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}

	// 回退必须完成正常的 SOCKS5 握手，客户端才不会挂在一个未应答的连接上。
	readSocks5Reply(t, br)
	select {
	case s := <-got:
		if s != "hello" {
			t.Errorf("upstream received %q, want %q", s, "hello")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not receive relayed bytes")
	}
}

func TestHandleTCPDNSProxyUpstreamFailure(t *testing.T) {
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	rt.AddProxyDomain("proxy.example.com")

	tr := &mockTransport{}
	srv := newTCPDNSTestServer(t, rt, tr)
	client, br := serveTCPDNSHandler(t, srv, "223.5.5.5:53")

	q := new(dns.Msg)
	q.SetQuestion("proxy.example.com.", dns.TypeA)
	q.Id = 0x2222
	if err := writeTCPDNSMessage(client, q); err != nil {
		t.Fatalf("write query: %v", err)
	}

	readSocks5Reply(t, br)
	resp, err := readTCPDNSMessage(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Id != 0x2222 {
		t.Errorf("response id = %#x, want %#x", resp.Id, 0x2222)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %d, want SERVFAIL (mock upstream silent)", resp.Rcode)
	}
	if got := tr.openCalls(); got != 1 {
		t.Errorf("transport open calls = %d, want 1 (proxied query must open a tunnel exchange)", got)
	}
}

func TestHandleTCPDNSFallbackNonDNS(t *testing.T) {
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	// 本地 TCP 目标：验证回退中继把非 DNS 字节原样送达（而非丢弃或泄漏到隧道外）。
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { targetLn.Close() }) //nolint:errcheck
	got := make(chan string, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		buf := make([]byte, 32)
		n, _ := conn.Read(buf)
		got <- string(buf[:n])
	}()

	srv := newTCPDNSTestServer(t, rt, &mockTransport{})
	target := targetLn.Addr().String() // 127.0.0.1:* → LAN → 直连
	client, br := serveTCPDNSHandler(t, srv, target)

	// "he" 会被当作长度字段（0x6865 = 26725），后续字节读不满 → 首条报文解析失败
	// → 回退普通中继，且不丢已读字节。
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write non-dns bytes: %v", err)
	}
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}

	readSocks5Reply(t, br)
	select {
	case s := <-got:
		if s != "hello" {
			t.Errorf("target received %q, want %q", s, "hello")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target did not receive relayed bytes")
	}
}

func TestHandleTCPDNSMultipleQueries(t *testing.T) {
	easydns.ResetResolveState()
	oldDNS := clientconfig.DirectDNSServers
	clientconfig.DirectDNSServers = []string{startUDPDNSResponder(t, "1.2.3.4")}
	t.Cleanup(func() { clientconfig.DirectDNSServers = oldDNS })

	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	rt.AddDirectDomain("direct.example.com")
	rt.AddProxyDomain("proxy.example.com")

	srv := newTCPDNSTestServer(t, rt, &mockTransport{})
	client, br := serveTCPDNSHandler(t, srv, "223.5.5.5:53")

	// 第一条：直连解析。
	q1 := new(dns.Msg)
	q1.SetQuestion("direct.example.com.", dns.TypeA)
	q1.Id = 1
	if err := writeTCPDNSMessage(client, q1); err != nil {
		t.Fatalf("write query 1: %v", err)
	}
	readSocks5Reply(t, br)
	r1, err := readTCPDNSMessage(br, nil)
	if err != nil {
		t.Fatalf("read response 1: %v", err)
	}
	if r1.Id != 1 || len(r1.Answer) != 1 {
		t.Fatalf("response 1 = id %d, %d answers; want id 1, 1 answer", r1.Id, len(r1.Answer))
	}

	// 第二条：代理（mock 上游沉默 → SERVFAIL）。
	q2 := new(dns.Msg)
	q2.SetQuestion("proxy.example.com.", dns.TypeA)
	q2.Id = 2
	if err := writeTCPDNSMessage(client, q2); err != nil {
		t.Fatalf("write query 2: %v", err)
	}
	r2, err := readTCPDNSMessage(br, nil)
	if err != nil {
		t.Fatalf("read response 2: %v", err)
	}
	if r2.Id != 2 || r2.Rcode != dns.RcodeServerFailure {
		t.Fatalf("response 2 = id %d, rcode %d; want id 2, SERVFAIL", r2.Id, r2.Rcode)
	}

	// 第三条：同一连接上命中第一条的直连缓存。
	q3 := new(dns.Msg)
	q3.SetQuestion("direct.example.com.", dns.TypeA)
	q3.Id = 3
	if err := writeTCPDNSMessage(client, q3); err != nil {
		t.Fatalf("write query 3: %v", err)
	}
	r3, err := readTCPDNSMessage(br, nil)
	if err != nil {
		t.Fatalf("read response 3: %v", err)
	}
	if r3.Id != 3 || len(r3.Answer) != 1 {
		t.Fatalf("response 3 = id %d, %d answers; want id 3, 1 answer (cache hit)", r3.Id, len(r3.Answer))
	}
}

// TestHandleTCPDNSProxyExchangeRecreatedAfterFailure 覆盖失效交换残留的回归：
// 第一次代理查询失败（上游静默 → SERVFAIL）后，残留的已关闭交换必须从
// s.udpExch 移除，第二次代理查询要重建新交换（transport openCalls 增加到 2），
// 而不是命中残留交换导致该连接后续代理查询永久 SERVFAIL。
func TestHandleTCPDNSProxyExchangeRecreatedAfterFailure(t *testing.T) {
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	rt.AddProxyDomain("proxy.example.com")

	tr := &mockTransport{}
	srv := newTCPDNSTestServer(t, rt, tr)
	client, br := serveTCPDNSHandler(t, srv, "223.5.5.5:53")

	// 第一条代理查询：mock 上游静默 → SERVFAIL，交换被作废并从 map 移除。
	q1 := new(dns.Msg)
	q1.SetQuestion("proxy.example.com.", dns.TypeA)
	q1.Id = 1
	if err := writeTCPDNSMessage(client, q1); err != nil {
		t.Fatalf("write query 1: %v", err)
	}
	readSocks5Reply(t, br)
	r1, err := readTCPDNSMessage(br, nil)
	if err != nil {
		t.Fatalf("read response 1: %v", err)
	}
	if r1.Rcode != dns.RcodeServerFailure {
		t.Fatalf("response 1 rcode = %d, want SERVFAIL", r1.Rcode)
	}

	// 第二条代理查询：必须重建新交换并再次走代理路径，仍回 SERVFAIL。
	q2 := new(dns.Msg)
	q2.SetQuestion("proxy.example.com.", dns.TypeA)
	q2.Id = 2
	if err := writeTCPDNSMessage(client, q2); err != nil {
		t.Fatalf("write query 2: %v", err)
	}
	r2, err := readTCPDNSMessage(br, nil)
	if err != nil {
		t.Fatalf("read response 2: %v", err)
	}
	if r2.Id != 2 || r2.Rcode != dns.RcodeServerFailure {
		t.Fatalf("response 2 = id %d, rcode %d; want id 2, SERVFAIL", r2.Id, r2.Rcode)
	}
	if got := tr.openCalls(); got != 2 {
		t.Errorf("transport open calls = %d, want 2 (stale exchange must be invalidated and rebuilt)", got)
	}
}
