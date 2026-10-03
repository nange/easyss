package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

// 本文件覆盖 UDP 中继对「原始字节」计数器的记账。托盘下载速度与 /stats 的
// upload_speed/download_speed 只由 rawBytesSent/rawBytesRecv 驱动（见
// stats.speedLoop），而 UDP 交换不经过 relay.Bidirectional——经隧道的 TCP 中继
// 唯一的记账点，因此所有经隧道的 UDP 路径都必须自己记账：漏掉任何一条，只要该
// 路径上有流量（最典型的是 QUIC/HTTP-3 的 4K 视频），速度显示就会长时间停在 0，
// 而隧道其实正在满速传输。
//
// 口径是"只统计经隧道的流量"：直连 UDP 与直连 TCP（route.go 的 relayTCP/
// copyHalfClose）都不计入，因为直连流量不经服务器。

// scriptedUDPStream 是一个 transport.Stream：Write 追加到可回读的缓冲（供用例
// 解密客户端写出的记录），Read 从注入缓冲读取（供用例冒充服务端下发记录）。
type scriptedUDPStream struct {
	mu       sync.Mutex
	written  []byte
	injected bytes.Buffer
	wake     chan struct{}
}

func newScriptedUDPStream() *scriptedUDPStream {
	return &scriptedUDPStream{wake: make(chan struct{}, 1)}
}

func (s *scriptedUDPStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.written = append(s.written, p...)
	s.mu.Unlock()
	return len(p), nil
}

func (s *scriptedUDPStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	if s.injected.Len() > 0 {
		n, _ := s.injected.Read(p)
		s.mu.Unlock()
		return n, nil
	}
	s.mu.Unlock()

	select {
	case <-s.wake:
		return 0, nil // 被唤醒后重试一次读取
	case <-time.After(time.Second):
		return 0, io.EOF // 用例不再注入数据：结束接收循环
	}
}

func (s *scriptedUDPStream) CloseWrite() error { return nil }
func (s *scriptedUDPStream) Close() error      { return nil }

// inject 追加一段用例预先加密好的 s2c 记录，并唤醒阻塞中的 Read。
func (s *scriptedUDPStream) inject(record []byte) {
	s.mu.Lock()
	s.injected.Write(record)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *scriptedUDPStream) writtenBytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.written...)
}

// udpSessionCodec 用交换创建时的 salt 派生出同一套会话密钥，使用例能像服务端
// 一样解码客户端写出的记录、编码下发记录。
type udpSessionCodec struct {
	sk     *crypto.StreamKeys
	method protocol.Method
}

func newUDPSessionCodec(t *testing.T, masterKey []byte, saltB64 string) *udpSessionCodec {
	t.Helper()

	salt, err := base64.RawURLEncoding.DecodeString(saltB64)
	if err != nil {
		t.Fatalf("decode salt %q: %v", saltB64, err)
	}
	sk, err := crypto.NewStreamKeys(masterKey, salt, config.EndpointUDP)
	if err != nil {
		t.Fatalf("NewStreamKeys: %v", err)
	}
	return &udpSessionCodec{sk: sk, method: protocol.MethodAES256GCM}
}

// parseWrittenDatagrams 解密目前已写出的全部记录，返回其中的 DATAGRAM 载荷。
// 它镜像服务端的读取顺序：首条记录是 bootstrap 阶段（握手 + 合并进来的首个
// DATAGRAM + padding），其余是 session 阶段。尾部不完整的记录（shaper 正在写）
// 直接忽略：调用方用 waitFor 轮询重试。
func (c *udpSessionCodec) parseWrittenDatagrams(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	if len(raw) < protocol.MaxCipherLenSize {
		return nil
	}

	var datagrams [][]byte
	first, err := c.sk.ReadFirstRecord(bytes.NewReader(raw))
	if err != nil {
		return nil // 首条记录尚未写完
	}
	for _, f := range first.Leftover {
		if f.Type == protocol.FrameDATAGRAM {
			datagrams = append(datagrams, append([]byte(nil), f.Payload...))
		}
	}

	// 首条记录的线上长度：3 字节 cipher_len + ciphertext。
	firstLen := protocol.MaxCipherLenSize + (int(raw[0])<<16 | int(raw[1])<<8 | int(raw[2]))
	if len(raw) <= firstLen {
		return datagrams
	}

	rx, err := c.sk.NewReader(bytes.NewReader(raw[firstLen:]), crypto.DirC2S, c.method)
	if err != nil {
		t.Fatalf("NewReader(c2s): %v", err)
	}
	for {
		frame, err := rx.ReadFrame()
		if err != nil {
			return datagrams // io.EOF（记录边界）或尾部记录尚不完整
		}
		if frame.Type == protocol.FrameDATAGRAM {
			datagrams = append(datagrams, append([]byte(nil), frame.Payload...))
		}
	}
}

// serverRecord 编码一条由服务端发往客户端的记录，其中只含一个 DATAGRAM 帧
// （即服务端从远端读到的数据报，不带填充与 cover）。
func (c *udpSessionCodec) serverRecord(t *testing.T, payload []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w, err := c.sk.NewWriter(&buf, crypto.DirS2C, c.method)
	if err != nil {
		t.Fatalf("NewWriter(s2c): %v", err)
	}
	if err := w.WriteRecord(protocol.EncodeFrames([]protocol.Frame{protocol.NewFrameDATAGRAM(payload)})); err != nil {
		t.Fatalf("write s2c record: %v", err)
	}
	return buf.Bytes()
}

// newUDPStatsServer 构造一个使用给定 StreamHandler（其传输层交付用例控制的流）
// 的 SOCKS5 服务器，并登记一个带真实 socket 的 UDP 中继。
func newUDPStatsServer(t *testing.T, h *StreamHandler, clientPort int) (*Socks5Server, *udpRelay) {
	t.Helper()

	srv, err := NewSocks5Server(Socks5Options{
		ListenAddr: "127.0.0.1:0",
		Handler:    h,
		Method:     protocol.MethodAES256GCM,
		Timeouts: config.Timeouts{
			Base:       30 * time.Second,
			Dial:       10 * time.Second,
			StreamIdle: 30 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	client := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: clientPort}
	return srv, newDisposableUDPRelay(t, srv, client)
}

// TestUDPProxyRelayCountsRawBytes 覆盖经隧道的 UDP 中继（QUIC/HTTP-3 的主力路径）：
// 交换创建时的首个数据报（会合并进引导记录，因此不走 UDPExchange.Send）与后续
// 数据报都必须计入上行，服务端下发的数据报必须计入下行。
func TestUDPProxyRelayCountsRawBytes(t *testing.T) {
	stream := newScriptedUDPStream()
	tr := &saltCapturingTransport{inner: &mockTransport{streams: []transport.Stream{stream}}}
	h := newTestStreamHandler(tr)
	srv, relay := newUDPStatsServer(t, h, 43210)

	target := "142.250.0.1:443" // 真实场景里是 QUIC 的 UDP 443
	first := []byte("first-datagram-merged-into-bootstrap")
	follow := []byte("follow-up-datagram")
	reply := []byte("server-datagram-reply")

	before := stats.Collect()
	if err := srv.proxyUDPRelay(relay, target, first); err != nil {
		t.Fatalf("proxyUDPRelay(first): %v", err)
	}
	if _, ok := srv.udp.exchangeFor(relay.datagramSource().String() + "_" + target); !ok {
		t.Fatal("exchange was not registered")
	}
	if err := srv.proxyUDPRelay(relay, target, follow); err != nil {
		t.Fatalf("proxyUDPRelay(follow): %v", err)
	}

	// 用例冒充服务端下发一条数据报。
	codec := newUDPSessionCodec(t, h.masterKey, tr.salts[0])
	stream.inject(codec.serverRecord(t, reply))

	waitFor(t, 5*time.Second, func() bool {
		return stats.Collect().RawBytesRecv-before.RawBytesRecv == int64(len(reply))
	})
	after := stats.Collect()

	if got, want := after.RawBytesSent-before.RawBytesSent, int64(len(first)+len(follow)); got != want {
		t.Errorf("raw upload delta = %d, want %d (QUIC upstream must be counted, including the bootstrap-merged first datagram)", got, want)
	}
	if got, want := after.RawBytesRecv-before.RawBytesRecv, int64(len(reply)); got != want {
		t.Errorf("raw download delta = %d, want %d", got, want)
	}
}

// TestUDPProxyRelayTunnelsEachPayloadOnce 固化"每个数据报恰好被隧道化一次"：首个
// 数据报合并进引导记录、后续走 Send，解密后的 DATAGRAM 序列必须与客户端发出的
// 一致（记账不应改变转发行为，反之亦然）。
func TestUDPProxyRelayTunnelsEachPayloadOnce(t *testing.T) {
	stream := newScriptedUDPStream()
	tr := &saltCapturingTransport{inner: &mockTransport{streams: []transport.Stream{stream}}}
	h := newTestStreamHandler(tr)
	srv, relay := newUDPStatsServer(t, h, 43211)

	target := "142.250.0.2:443"
	payloads := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	for _, p := range payloads {
		if err := srv.proxyUDPRelay(relay, target, p); err != nil {
			t.Fatalf("proxyUDPRelay(%q): %v", p, err)
		}
	}
	key := relay.datagramSource().String() + "_" + target
	ue, ok := srv.udp.exchangeFor(key)
	if !ok {
		t.Fatal("exchange was not registered")
	}
	if err := ue.tx.Flush(); err != nil {
		t.Fatalf("flush shaper: %v", err)
	}

	codec := newUDPSessionCodec(t, h.masterKey, tr.salts[0])
	var got [][]byte
	// shaper 以 1ms 批处理窗口异步冲刷，且首个数据报由引导记录承载，因此轮询
	// 直到解析出全部数据报。
	waitFor(t, 5*time.Second, func() bool {
		got = codec.parseWrittenDatagrams(t, stream.writtenBytes())
		return len(got) >= len(payloads)
	})
	if len(got) != len(payloads) {
		t.Fatalf("tunnel carried %d DATAGRAM frames, want %d", len(got), len(payloads))
	}
	for i, want := range payloads {
		if !bytes.Equal(got[i], want) {
			t.Errorf("datagram %d = %q, want %q", i, got[i], want)
		}
	}
}

// TestUDPDirectRelayExcludedFromSpeedCounters 固化直连 UDP 与速度计数器的关系：
// 计数器只统计经隧道的流量，直连流量（不经服务器）不计入。这条口径必须与直连
// TCP（route.go 的 relayTCP/copyHalfClose）一致，否则同一条直连规则下的 QUIC
// 与 TCP 会得到两种口径。
//
// 用例走完整的 SOCKS5 UDP ASSOCIATE 路径：回声必须真的回到客户端，否则"没有
// 计数"可能只是中继根本没跑起来。
func TestUDPDirectRelayExcludedFromSpeedCounters(t *testing.T) {
	echoAddr, stopEcho := startUDPEcho(t)
	defer stopEcho()

	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleDirect, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	srv := newTestSocks5ServerWithRouter(t, freeLoopbackAddr(t), rt)
	startDone := make(chan error, 1)
	go func() { startDone <- srv.Start() }()
	t.Cleanup(func() {
		_ = srv.Close()
		select {
		case <-startDone:
		case <-time.After(5 * time.Second):
			t.Error("Socks5Server.Start did not return after Close")
		}
	})
	if err := waitListenerUp(srv.listenAddr, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	ctrl, relayAddr := socks5Associate(t, srv.listenAddr)
	defer ctrl.Close() //nolint:errcheck
	client, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatalf("dial relay udp: %v", err)
	}
	defer client.Close() //nolint:errcheck

	payload := []byte("direct-udp-payload-0123456789")
	_, frame := buildUDPFrame(t, echoAddr, payload)

	before := stats.Collect()
	const rounds = 5
	for range rounds {
		if _, err := client.Write(frame); err != nil {
			t.Fatalf("write datagram: %v", err)
		}
		if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		buf := make([]byte, 2048)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("read relayed echo: %v", err)
		}
		if _, got := parseUDPFrame(t, buf[:n]); !bytes.Equal(got, payload) {
			t.Fatalf("echo payload = %q, want %q", got, payload)
		}
	}

	after := stats.Collect()
	if got := after.RawBytesSent - before.RawBytesSent; got != 0 {
		t.Errorf("raw upload delta = %d, want 0 (direct traffic must stay out of the speed counters)", got)
	}
	if got := after.RawBytesRecv - before.RawBytesRecv; got != 0 {
		t.Errorf("raw download delta = %d, want 0 (direct traffic must stay out of the speed counters)", got)
	}
}

// TestUDPProxyDNSRepliesCountRawBytes 覆盖经隧道的 DNS 交换：它是 udpPool.receiveLoop
// 的第二个使用者（应答走 onData 回调而非 SOCKS5 中继），上下行都必须记账。
func TestUDPProxyDNSRepliesCountRawBytes(t *testing.T) {
	stream := newScriptedUDPStream()
	tr := &saltCapturingTransport{inner: &mockTransport{streams: []transport.Stream{stream}}}
	h := newTestStreamHandler(tr)

	pool := newUDPPool(udpPoolOptions{
		OpenExchange: func(ctx context.Context, target string, firstPayload []byte) (*UDPExchange, error) {
			return h.OpenUDPExchange(ctx, target, protocol.MethodAES256GCM, firstPayload)
		},
	})
	pool.start()
	t.Cleanup(pool.close)

	// 应答会走完整的代理 DNS 后处理（AAAA 剥离、缓存、学习），因此拦截器需要
	// 真实的 Router 与 Cache。
	rt, err := router.New(router.Config{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	d := &dnsInterceptor{router: rt, cache: easydns.NewCache(""), pool: pool, respTimeout: time.Minute}

	query := new(dns.Msg)
	query.SetQuestion("www.youtube.com.", dns.TypeA)
	raw, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	reply := new(dns.Msg)
	reply.SetReply(query)
	reply.Answer = append(reply.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "www.youtube.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("142.250.0.3").To4(),
	})
	packed, err := reply.Pack()
	if err != nil {
		t.Fatalf("pack reply: %v", err)
	}

	delivered := make(chan []byte, 1)
	before := stats.Collect()
	req := udpDNSQuery{
		raw: raw,
		msg: query,
		src: "127.0.0.1:53000",
		dst: "8.8.8.8:53",
		reply: udpReply{raw: func(data []byte) {
			select {
			case delivered <- data:
			default:
			}
		}},
	}
	if err := d.proxyUDPQuery(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43213}, req, dnsPlan{}); err != nil {
		t.Fatalf("proxyUDPQuery: %v", err)
	}

	codec := newUDPSessionCodec(t, h.masterKey, tr.salts[0])
	stream.inject(codec.serverRecord(t, packed))

	select {
	case <-delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("tunneled DNS reply was never delivered to the client")
	}

	after := stats.Collect()
	if got, want := after.RawBytesRecv-before.RawBytesRecv, int64(len(packed)); got != want {
		t.Errorf("raw download delta = %d, want %d", got, want)
	}
	if got, want := after.RawBytesSent-before.RawBytesSent, int64(len(raw)); got != want {
		t.Errorf("raw upload delta = %d, want %d", got, want)
	}
}

// waitFor 轮询 cond 直到为真或超时，使用例不依赖固定 sleep。
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition was not met within %v", timeout)
}
