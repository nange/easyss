package nextproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSocks5UDPProxy 是一个最小的、支持 UDP ASSOCIATE 的 SOCKS5 服务端。
// 它不依赖被测实现：握手、关联应答与数据报解封装都按 RFC 1928 独立写出，
// 因此测试验证的是"线上字节"，而不是两份相同的错误假设。
type fakeSocks5UDPProxy struct {
	t *testing.T

	listener net.Listener
	// relay 是关联建立后返回给客户端的 UDP 地址；它把收到的数据报按目标地址
	// 转发到真实的 UDP 服务端，再把应答原样封装回去。
	relay *net.UDPConn

	// requireAuth 为 true 时只接受用户名/密码认证。
	requireAuth bool
	user        string
	password    string
	// replyCode 非 0 时用于拒绝 ASSOCIATE（测试错误路径）。
	replyCode byte
	// wildcardRelay 为 true 时应答 0.0.0.0:<port>，逼客户端用控制连接的对端
	// 地址替换通配地址。
	wildcardRelay bool

	mu       sync.Mutex
	gotUser  string
	gotPass  string
	authSent bool
	udpSeen  []string // 收到的每个数据报的 "host:port" 目标
	closed   chan struct{}
}

func newFakeSocks5UDPProxy(t *testing.T, requireAuth bool, user, password string) *fakeSocks5UDPProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		ln.Close() //nolint:errcheck
		t.Fatalf("listen udp: %v", err)
	}

	p := &fakeSocks5UDPProxy{
		t:           t,
		listener:    ln,
		relay:       relay,
		requireAuth: requireAuth,
		user:        user,
		password:    password,
		closed:      make(chan struct{}),
	}
	go p.serve()
	go p.serveRelay()
	t.Cleanup(func() {
		close(p.closed)
		ln.Close()    //nolint:errcheck
		relay.Close() //nolint:errcheck
	})
	return p
}

func (p *fakeSocks5UDPProxy) addr() string { return p.listener.Addr().String() }

func (p *fakeSocks5UDPProxy) authReceived() (string, string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gotUser, p.gotPass, p.authSent
}

func (p *fakeSocks5UDPProxy) datagramTargets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.udpSeen...)
}

func (p *fakeSocks5UDPProxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *fakeSocks5UDPProxy) handle(conn net.Conn) {
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 方法协商：VER NMETHODS METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	if head[0] != socksVersion5 {
		p.t.Errorf("fake proxy: unexpected version %d", head[0])
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	chosen := byte(socksAuthNoneRequired)
	if p.requireAuth {
		chosen = socksAuthNoAcceptable
		if slices.Contains(methods, socksAuthUserPass) {
			chosen = socksAuthUserPass
		}
	}
	if _, err := conn.Write([]byte{socksVersion5, chosen}); err != nil {
		return
	}
	if chosen == socksAuthNoAcceptable {
		return
	}
	if chosen == socksAuthUserPass {
		if !p.readUserPass(conn) {
			return
		}
	}

	// 命令请求：VER CMD RSV ATYP ADDR PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[1] != socksCmdUDPAssociate {
		_, _ = conn.Write([]byte{socksVersion5, 0x07, 0, socksATYPIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := readSocks5Addr(conn, req[3]); err != nil {
		return
	}
	portBytes := make([]byte, socksPortLen)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return
	}

	if p.replyCode != 0 {
		_, _ = conn.Write([]byte{socksVersion5, p.replyCode, 0, socksATYPIPv4, 0, 0, 0, 0, 0, 0})
		return
	}

	relayAddr := p.relay.LocalAddr().(*net.UDPAddr)
	ip := relayAddr.IP.To4()
	if p.wildcardRelay {
		ip = net.IPv4zero.To4()
	}
	reply := []byte{socksVersion5, socksReplySucceeded, 0, socksATYPIPv4}
	reply = append(reply, ip...)
	reply = binary.BigEndian.AppendUint16(reply, uint16(relayAddr.Port))
	if _, err := conn.Write(reply); err != nil {
		return
	}

	// 关联建立：控制连接必须保持打开，直到客户端关闭它。
	_ = conn.SetDeadline(time.Time{})
	buf := make([]byte, 1)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

func (p *fakeSocks5UDPProxy) readUserPass(conn net.Conn) bool {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return false
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return false
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return false
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return false
	}

	p.mu.Lock()
	p.gotUser, p.gotPass, p.authSent = string(user), string(pass), true
	p.mu.Unlock()

	status := byte(socksAuthStatusOK)
	if string(user) != p.user || string(pass) != p.password {
		status = 0x01
	}
	_, _ = conn.Write([]byte{socksAuthVersion, status})
	return status == socksAuthStatusOK
}

// serveRelay 把收到的数据报按封装里的目标地址真实转发出去，再封装回客户端。
// 这样测试可以对着一个真实的 UDP 服务端验证完整往返，而不是让假代理自问自答。
func (p *fakeSocks5UDPProxy) serveRelay() {
	buf := make([]byte, udpAssociateReadBuffer)
	for {
		n, clientAddr, err := p.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		dst, payload, parseErr := parseSocks5UDPDatagram(buf[:n])
		if parseErr != nil {
			p.t.Errorf("fake proxy: bad datagram from client: %v", parseErr)
			continue
		}
		p.mu.Lock()
		p.udpSeen = append(p.udpSeen, dst)
		p.mu.Unlock()

		go p.forward(clientAddr, dst, payload)
	}
}

func (p *fakeSocks5UDPProxy) forward(clientAddr *net.UDPAddr, dst string, payload []byte) {
	upstream, err := net.Dial("udp", dst)
	if err != nil {
		return
	}
	defer upstream.Close() //nolint:errcheck
	_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := upstream.Write(payload); err != nil {
		return
	}
	resp := make([]byte, udpAssociateReadBuffer)
	n, err := upstream.Read(resp)
	if err != nil {
		return
	}
	framed, err := frameSocks5UDPDatagram(dst, make([]byte, 0, n+22), resp[:n])
	if err != nil {
		return
	}
	_, _ = p.relay.WriteToUDP(framed, clientAddr)
}

// startUDPEcho 起一个真实的 UDP 回显服务端，返回其地址。
func startUDPEcho(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()
	return conn.LocalAddr().String()
}

func newTestNextProxy(t *testing.T, proxyAddr string, enableUDP bool) *NextProxy {
	t.Helper()
	np, err := New("socks5://"+proxyAddr, enableUDP, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	np.SetDialTimeout(5 * time.Second)
	return np
}

// TestDialUDPAssociateRoundTrip 是本文件的核心用例：经 next proxy 的 UDP
// 会话必须能双向收发数据报。回归前（把 "udp" 交给 x/net/proxy 的 CONNECT
// 拨号器）这一步会以 "network not implemented" 失败——正是线上那次
// DNS 全面超时的根因。
func TestDialUDPAssociateRoundTrip(t *testing.T) {
	echo := startUDPEcho(t)
	proxy := newFakeSocks5UDPProxy(t, false, "", "")
	np := newTestNextProxy(t, proxy.addr(), true)

	conn, err := np.DialContext(context.Background(), "udp", echo)
	if err != nil {
		t.Fatalf("DialContext(udp) = %v, want success", err)
	}
	defer conn.Close() //nolint:errcheck

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write = %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline = %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read = %v", err)
	}
	if got, want := string(buf[:n]), "echo:ping"; got != want {
		t.Errorf("Read = %q, want %q", got, want)
	}

	targets := proxy.datagramTargets()
	if len(targets) != 1 || targets[0] != echo {
		t.Errorf("upstream saw datagram targets %v, want [%s]", targets, echo)
	}
}

// TestDialUDPAssociateRequiresEnableUDP 钉住配置门控：enable_udp=false 时
// 绝不能悄悄建立关联（调用方应该已经据此走直连）。
func TestDialUDPAssociateRequiresEnableUDP(t *testing.T) {
	echo := startUDPEcho(t)
	proxy := newFakeSocks5UDPProxy(t, false, "", "")
	np := newTestNextProxy(t, proxy.addr(), false)

	if _, err := np.DialContext(context.Background(), "udp", echo); err == nil {
		t.Fatal("DialContext(udp) with enable_udp=false = nil, want error")
	}
}

// TestDialUDPAssociateAuth 覆盖用户名/密码认证：CONNECT 与 UDP ASSOCIATE
// 必须走同一套凭据解析。
func TestDialUDPAssociateAuth(t *testing.T) {
	echo := startUDPEcho(t)
	proxy := newFakeSocks5UDPProxy(t, true, "u1", "p1")

	np, err := New("socks5://u1:p1@"+proxy.addr(), true, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	np.SetDialTimeout(5 * time.Second)

	conn, err := np.DialContext(context.Background(), "udp", echo)
	if err != nil {
		t.Fatalf("DialContext(udp) = %v, want success", err)
	}
	defer conn.Close() //nolint:errcheck

	user, pass, sent := proxy.authReceived()
	if !sent || user != "u1" || pass != "p1" {
		t.Errorf("upstream got auth (%q,%q,sent=%v), want (u1,p1,true)", user, pass, sent)
	}

	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatalf("Write = %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read = %v", err)
	}
	if got := string(buf[:n]); got != "echo:hi" {
		t.Errorf("Read = %q, want %q", got, "echo:hi")
	}
}

// TestDialUDPAssociateWildcardRelay 覆盖上游应答 0.0.0.0:<port> 的情况：
// 通配地址不能当作发送目标，必须替换成控制连接的对端地址。
func TestDialUDPAssociateWildcardRelay(t *testing.T) {
	echo := startUDPEcho(t)
	proxy := newFakeSocks5UDPProxy(t, false, "", "")
	proxy.wildcardRelay = true
	np := newTestNextProxy(t, proxy.addr(), true)

	conn, err := np.DialContext(context.Background(), "udp", echo)
	if err != nil {
		t.Fatalf("DialContext(udp) = %v, want success", err)
	}
	defer conn.Close() //nolint:errcheck

	if _, err := conn.Write([]byte("wild")); err != nil {
		t.Fatalf("Write = %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read = %v", err)
	}
	if got := string(buf[:n]); got != "echo:wild" {
		t.Errorf("Read = %q, want %q", got, "echo:wild")
	}
}

// TestDialUDPAssociateRejected 覆盖上游拒绝 ASSOCIATE 时的错误报告：
// 错误里必须带上 RFC 1928 的应答码含义，而不是一个裸的 EOF。
func TestDialUDPAssociateRejected(t *testing.T) {
	echo := startUDPEcho(t)
	proxy := newFakeSocks5UDPProxy(t, false, "", "")
	proxy.replyCode = 0x07 // command not supported
	np := newTestNextProxy(t, proxy.addr(), true)

	_, err := np.DialContext(context.Background(), "udp", echo)
	if err == nil {
		t.Fatal("DialContext(udp) = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "command not supported") {
		t.Errorf("error = %v, want it to name the reply code", err)
	}
}

// TestDialContextUDPUnreachableProxy 覆盖控制连接建不起来时的错误路径。
func TestDialContextUDPUnreachableProxy(t *testing.T) {
	np, err := New("socks5://127.0.0.1:1", true, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	np.SetDialTimeout(500 * time.Millisecond)

	if _, err := np.DialContext(context.Background(), "udp", "127.0.0.1:9"); err == nil {
		t.Fatal("DialContext(udp) against a closed port = nil error, want failure")
	}
}

// TestUDPAssociateConnCloseUnblocksRead 钉住"控制连接关闭 ⇒ 数据面立即结束"：
// 上游一旦撤销关联，阻塞中的 Read 必须返回，而不是僵死到会话空闲超时。
func TestUDPAssociateConnCloseUnblocksRead(t *testing.T) {
	proxy := newFakeSocks5UDPProxy(t, false, "", "")
	np := newTestNextProxy(t, proxy.addr(), true)

	conn, err := np.DialContext(context.Background(), "udp", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("DialContext(udp) = %v", err)
	}
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := conn.Read(buf)
		readErr <- err
	}()

	select {
	case err := <-readErr:
		t.Fatalf("Read returned before Close: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	select {
	case err := <-readErr:
		if err == nil {
			t.Error("Read after Close = nil error, want failure")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read stayed blocked after Close")
	}
}

// TestFrameParseSocks5UDPDatagram 覆盖封帧/解帧的边界：两种地址族、域名目标、
// 分片标志与各类短报文。解析出的目标必须与封帧时的目标逐字一致。
func TestFrameParseSocks5UDPDatagram(t *testing.T) {
	cases := []struct {
		name    string
		dst     string
		payload string
	}{
		{"ipv4", "8.8.8.8:53", "query-bytes"},
		{"ipv6", "[2001:db8::1]:443", "v6-payload"},
		{"domain", "dns.google:53", "name-payload"},
		{"empty payload", "1.1.1.1:53", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			framed, err := frameSocks5UDPDatagram(tc.dst, nil, []byte(tc.payload))
			if err != nil {
				t.Fatalf("frame: %v", err)
			}
			src, payload, err := parseSocks5UDPDatagram(framed)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if src != tc.dst {
				t.Errorf("parsed source = %q, want %q", src, tc.dst)
			}
			if string(payload) != tc.payload {
				t.Errorf("parsed payload = %q, want %q", payload, tc.payload)
			}
		})
	}

	t.Run("bad port", func(t *testing.T) {
		if _, err := frameSocks5UDPDatagram("1.1.1.1:notaport", nil, nil); err == nil {
			t.Error("frame with bad port = nil error, want failure")
		}
	})
	t.Run("oversized domain", func(t *testing.T) {
		if _, err := frameSocks5UDPDatagram(strings.Repeat("a", 300)+":53", nil, nil); err == nil {
			t.Error("frame with oversized name = nil error, want failure")
		}
	})
	t.Run("short datagram", func(t *testing.T) {
		if _, _, err := parseSocks5UDPDatagram([]byte{0, 0, 0}); err == nil {
			t.Error("parse of a 3-byte datagram = nil error, want failure")
		}
	})
	t.Run("fragmented datagram", func(t *testing.T) {
		framed, err := frameSocks5UDPDatagram("1.1.1.1:53", nil, []byte("x"))
		if err != nil {
			t.Fatalf("frame: %v", err)
		}
		framed[2] = 1 // FRAG != 0
		if _, _, err := parseSocks5UDPDatagram(framed); err == nil {
			t.Error("parse of a fragmented datagram = nil error, want failure")
		}
	})
	t.Run("truncated header", func(t *testing.T) {
		framed, err := frameSocks5UDPDatagram("1.1.1.1:53", nil, []byte("x"))
		if err != nil {
			t.Fatalf("frame: %v", err)
		}
		if _, _, err := parseSocks5UDPDatagram(framed[:6]); err == nil {
			t.Error("parse of a truncated header = nil error, want failure")
		}
	})
	t.Run("unsupported atyp", func(t *testing.T) {
		if _, _, err := parseSocks5UDPDatagram([]byte{0, 0, 0, 0x09, 1, 2}); err == nil {
			t.Error("parse with bad ATYP = nil error, want failure")
		}
	})
}

// TestSocksReplyString 钉住应答码翻译，避免排障时只看到一个数字。
func TestSocksReplyString(t *testing.T) {
	cases := map[byte]string{
		socksReplySucceeded: "succeeded",
		0x07:                "command not supported",
		0x08:                "address type not supported",
		0x42:                "unknown reply code 66",
	}
	for code, want := range cases {
		if got := socksReplyString(code); got != want {
			t.Errorf("socksReplyString(%#x) = %q, want %q", code, got, want)
		}
	}
}

// TestUDPAddrFamilyAndNetwork 钉住地址族判定：本地地址的绑定与 socket 的族
// 都由它派生，判错会把 v4 地址绑给 v6 socket 而让拨号失败。
func TestUDPAddrFamilyAndNetwork(t *testing.T) {
	if got := udpAddrFamily(net.IPv4(127, 0, 0, 1)); got != 4 {
		t.Errorf("udpAddrFamily(v4) = %d, want 4", got)
	}
	if got := udpAddrFamily(net.ParseIP("2001:db8::1")); got != 6 {
		t.Errorf("udpAddrFamily(v6) = %d, want 6", got)
	}
	if got := udpNetworkFor(net.ParseIP("2001:db8::1")); got != "udp6" {
		t.Errorf("udpNetworkFor(v6) = %q, want udp6", got)
	}
	if got := udpNetworkFor(net.IPv4(1, 1, 1, 1)); got != "udp4" {
		t.Errorf("udpNetworkFor(v4) = %q, want udp4", got)
	}
}

// TestLocalAddrFor 覆盖"把本地地址钉在控制连接所用接口上"的选择逻辑：
// 同族才绑定，异构必须放弃绑定（把 v4 地址绑给 v6 socket 只会让拨号失败）。
func TestLocalAddrFor(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close() //nolint:errcheck
	server := <-accepted
	defer server.Close() //nolint:errcheck

	got := localAddrFor(client, net.IPv4(1, 1, 1, 1))
	if got == nil || !got.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("localAddrFor(v4 relay) = %v, want the control connection's 127.0.0.1", got)
	}
	if got := localAddrFor(client, net.ParseIP("2001:db8::1")); got != nil {
		t.Errorf("localAddrFor(v6 relay) = %v, want nil (family mismatch)", got)
	}
}

// TestCredentials 钉住 URL 凭据解析：CONNECT 与 UDP ASSOCIATE 共用它，
// 因此两条路径的认证行为不可能分叉。空凭据必须报告 ok=false（不启用认证
// 协商），而不是一个空的用户名/密码对。
func TestCredentials(t *testing.T) {
	proxy := newFakeSocks5UDPProxy(t, false, "", "")
	np := newTestNextProxy(t, proxy.addr(), true)
	if _, _, ok := np.credentials(); ok {
		t.Error("credentials() = ok for a URL without user info")
	}

	np2, err := New("socks5://user:pass@"+proxy.addr(), true, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	user, pass, ok := np2.credentials()
	if !ok || user != "user" || pass != "pass" {
		t.Errorf("credentials() = (%q,%q,%v), want (user,pass,true)", user, pass, ok)
	}
}

// TestFrameSocks5UDPDatagramReusesBuffer 钉住"复用调用方缓冲区"这一约定：
// 传入的 buf 必须被追加而不是被替换，否则每条数据报都会新分配一次——在
// DNS/QUIC 这种逐包路径上，那是每个数据报一次额外分配。
func TestFrameSocks5UDPDatagramReusesBuffer(t *testing.T) {
	buf := make([]byte, 0, 64)
	framed, err := frameSocks5UDPDatagram("1.1.1.1:53", buf, []byte("payload"))
	if err != nil {
		t.Fatalf("frame: %v", err)
	}
	if &framed[0] != &buf[:1][0] {
		t.Error("frameSocks5UDPDatagram allocated a new buffer instead of appending")
	}
	if want := 3 + 1 + 4 + 2 + len("payload"); len(framed) != want {
		t.Errorf("framed length = %d, want %d", len(framed), want)
	}
	if !strings.HasPrefix(fmt.Sprintf("% x", framed[:3]), "00 00 00") {
		t.Errorf("RSV/FRAG prefix = % x, want 00 00 00", framed[:3])
	}
}
