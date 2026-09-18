package proxy

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	clientconfig "github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/transport"
	"github.com/txthinking/socks5"
)

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

// startUDPDNSResponder 启动一个本地 UDP DNS 应答器：任意 A 查询回 A:1.2.3.4。
func startUDPDNSResponder(t *testing.T) string {
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
				A:   net.ParseIP("1.2.3.4"),
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
	msg, err := readTCPDNSMessage(bufio.NewReader(client))
	if err != nil {
		t.Fatalf("read round-trip: %v", err)
	}
	if len(msg.Question) != 1 || msg.Question[0].Name != "framing.example.com." {
		t.Errorf("question = %v, want framing.example.com.", msg.Question)
	}

	// 零长度：拒绝。
	if _, err := readTCPDNSMessage(bufio.NewReader(&bytesReader{data: []byte{0, 0}})); err == nil {
		t.Error("zero-length message accepted, want error")
	}
	// 超长：拒绝。
	if _, err := readTCPDNSMessage(bufio.NewReader(&bytesReader{data: []byte{0xff, 0xff}})); err == nil {
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
	oldDNS := clientconfig.DirectDNSServers
	clientconfig.DirectDNSServers = []string{startUDPDNSResponder(t)}
	t.Cleanup(func() { clientconfig.DirectDNSServers = oldDNS })

	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	rt.AddDirectDomain("direct.example.com")

	srv := newTCPDNSTestServer(t, rt, &mockTransport{})
	client, br := serveTCPDNSHandler(t, srv, "223.5.5.5:53")

	q := new(dns.Msg)
	q.SetQuestion("direct.example.com.", dns.TypeA)
	q.Id = 0x1234
	if err := writeTCPDNSMessage(client, q); err != nil {
		t.Fatalf("write query: %v", err)
	}

	readSocks5Reply(t, br)
	resp, err := readTCPDNSMessage(br)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Id != 0x1234 {
		t.Errorf("response id = %#x, want %#x", resp.Id, 0x1234)
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
	resp, err := readTCPDNSMessage(br)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Id != 0x1111 {
		t.Errorf("response id = %#x, want %#x", resp.Id, 0x1111)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %d, want Refused", resp.Rcode)
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
	resp, err := readTCPDNSMessage(br)
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
	clientconfig.DirectDNSServers = []string{startUDPDNSResponder(t)}
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
	r1, err := readTCPDNSMessage(br)
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
	r2, err := readTCPDNSMessage(br)
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
	r3, err := readTCPDNSMessage(br)
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
	r1, err := readTCPDNSMessage(br)
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
	r2, err := readTCPDNSMessage(br)
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
