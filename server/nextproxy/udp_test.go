package nextproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/transport/socks5"
)

// fakeSocks5UDPProxy 按 RFC 1928 自己读写方法协商、认证与命令应答，被测实现面对的是
// 真实的线上字节。只有数据报的封/解封装复用 socks5 包——那是对端实现，不是被测对象。
type fakeSocks5UDPProxy struct {
	t *testing.T

	listener net.Listener
	// relay 把收到的数据报按目标地址转发到真实 UDP 服务端，再把应答封装回去。
	relay *net.UDPConn

	requireAuth bool
	user        string
	password    string
	// replyCode 非 0 时用于拒绝 ASSOCIATE。
	replyCode byte
	// wildcardRelay 应答 0.0.0.0:<port>，逼客户端用控制连接的对端地址替换通配地址。
	wildcardRelay bool
	// domainRelay 用域名形态的中继地址，覆盖库的 Addr.UDPAddr() 对域名返回 nil 的分支。
	domainRelay string

	mu       sync.Mutex
	gotUser  string
	gotPass  string
	authSent bool
	udpSeen  []string // 收到的每个数据报的 "host:port" 目标

	// controlClosed 在某条控制连接被客户端关掉时关闭：连接没被建立时也会超时，
	// 因此不能用来证明连接建立过。
	closed        chan struct{}
	controlClosed chan struct{}
	controlOnce   sync.Once
}

func (p *fakeSocks5UDPProxy) waitControlClosed(timeout time.Duration) bool {
	select {
	case <-p.controlClosed:
		return true
	case <-time.After(timeout):
		return false
	}
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
		t:             t,
		listener:      ln,
		relay:         relay,
		requireAuth:   requireAuth,
		user:          user,
		password:      password,
		closed:        make(chan struct{}),
		controlClosed: make(chan struct{}),
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

func (p *fakeSocks5UDPProxy) markControlClosed() {
	p.controlOnce.Do(func() { close(p.controlClosed) })
}

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
	defer p.markControlClosed()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	if head[0] != socks5.Version {
		p.t.Errorf("fake proxy: unexpected version %d", head[0])
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	chosen := socks5.MethodNoAuth
	if p.requireAuth {
		chosen = 0xff // no acceptable methods
		if slices.Contains(methods, socks5.MethodUserPass) {
			chosen = socks5.MethodUserPass
		}
	}
	if _, err := conn.Write([]byte{socks5.Version, chosen}); err != nil {
		return
	}
	if chosen == 0xff {
		return
	}
	if chosen == socks5.MethodUserPass {
		if !p.readUserPass(conn) {
			return
		}
	}

	// 头四字节已在 req 里，只需按 ATYP 把地址与端口读完；socks5.ReadAddr 会从头再读一遍 ATYP。
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[1] != byte(socks5.CmdUDPAssociate) {
		_, _ = conn.Write([]byte{socks5.Version, 0x07, 0, socks5.AtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	var addrLen int
	switch req[3] {
	case socks5.AtypIPv4:
		addrLen = net.IPv4len
	case socks5.AtypIPv6:
		addrLen = net.IPv6len
	default:
		p.t.Errorf("fake proxy: unsupported request ATYP %#x", req[3])
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, addrLen+2)); err != nil {
		return
	}

	if p.replyCode != 0 {
		_, _ = conn.Write([]byte{socks5.Version, p.replyCode, 0, socks5.AtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}

	relayPort := uint16(p.relay.LocalAddr().(*net.UDPAddr).Port)
	// VER REP RSV 之后紧跟 ATYP：多写一个 0 会让客户端把 0x00 当成 ATYP。
	reply := []byte{socks5.Version, 0x00, 0}
	switch {
	case p.domainRelay != "":
		reply = append(reply, socks5.AtypDomainName, byte(len(p.domainRelay)))
		reply = append(reply, p.domainRelay...)
	case p.wildcardRelay:
		reply = append(reply, socks5.AtypIPv4)
		reply = append(reply, net.IPv4zero.To4()...)
	default:
		reply = append(reply, socks5.AtypIPv4)
		reply = append(reply, p.relay.LocalAddr().(*net.UDPAddr).IP.To4()...)
	}
	reply = binary.BigEndian.AppendUint16(reply, relayPort)
	if _, err := conn.Write(reply); err != nil {
		return
	}

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

	status := byte(0x00)
	if string(user) != p.user || string(pass) != p.password {
		status = 0x01
	}
	_, _ = conn.Write([]byte{0x01, status})
	return status == 0x00
}

// serveRelay 先按字节独立校验数据报，再按封装里的目标地址真实转发：
// 避免被测实现与它自己的编解码互相印证。
func (p *fakeSocks5UDPProxy) serveRelay() {
	buf := make([]byte, maxUDPDatagram)
	for {
		n, clientAddr, err := p.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		raw := buf[:n]
		if _, _, ok := parseVerbatimDatagram(raw); !ok {
			p.t.Errorf("fake proxy: malformed datagram from client: % x", raw)
			continue
		}
		addr, payload, parseErr := socks5.DecodeUDPPacket(raw)
		if parseErr != nil {
			p.t.Errorf("fake proxy: bad datagram from client: %v", parseErr)
			continue
		}
		p.mu.Lock()
		p.udpSeen = append(p.udpSeen, addr.String())
		p.mu.Unlock()

		go p.forward(clientAddr, addr, payload)
	}
}

// parseVerbatimDatagram 刻意不用 socks5 包：被测的 Read/Write 正是走那个包，
// 两侧一起错时测试仍会通过。长度校验也独立——库的 EncodeUDPPacket 不检查长度字段与实体吻合。
func parseVerbatimDatagram(raw []byte) (dst string, payload []byte, ok bool) {
	if len(raw) < 4 || raw[0] != 0 || raw[1] != 0 || raw[2] != 0 {
		return "", nil, false
	}

	var host string
	offset := 4
	switch raw[3] {
	case 0x01: // IPv4
		if len(raw) < offset+net.IPv4len+2 {
			return "", nil, false
		}
		host = net.IP(raw[offset : offset+net.IPv4len]).String()
		offset += net.IPv4len
	case 0x04: // IPv6
		if len(raw) < offset+net.IPv6len+2 {
			return "", nil, false
		}
		host = net.IP(raw[offset : offset+net.IPv6len]).String()
		offset += net.IPv6len
	case 0x03: // 域名：长度字段必须与实体吻合
		if len(raw) < offset+1 {
			return "", nil, false
		}
		length := int(raw[offset])
		offset++
		if len(raw) < offset+length+2 {
			return "", nil, false
		}
		host = string(raw[offset : offset+length])
		offset += length
	default:
		return "", nil, false
	}

	port := int(raw[offset])<<8 | int(raw[offset+1])
	offset += 2
	return net.JoinHostPort(host, strconv.Itoa(port)), raw[offset:], true
}

func (p *fakeSocks5UDPProxy) forward(clientAddr *net.UDPAddr, dst socks5.Addr, payload []byte) {
	upstream, err := net.Dial("udp", dst.String())
	if err != nil {
		return
	}
	defer upstream.Close() //nolint:errcheck
	_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := upstream.Write(payload); err != nil {
		return
	}
	resp := make([]byte, maxUDPDatagram)
	n, err := upstream.Read(resp)
	if err != nil {
		return
	}
	framed, err := socks5.EncodeUDPPacket(dst, resp[:n])
	if err != nil {
		return
	}
	_, _ = p.relay.WriteToUDP(framed, clientAddr)
}

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

// 防回归："udp" 交给 x/net/proxy 的 CONNECT 拨号器会以 "network not implemented" 失败，
// 那正是线上 DNS 全面超时的根因。
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

func TestDialUDPAssociateRequiresEnableUDP(t *testing.T) {
	echo := startUDPEcho(t)
	proxy := newFakeSocks5UDPProxy(t, false, "", "")
	np := newTestNextProxy(t, proxy.addr(), false)

	if _, err := np.DialContext(context.Background(), "udp", echo); err == nil {
		t.Fatal("DialContext(udp) with enable_udp=false = nil, want error")
	}
}

// CONNECT 与 UDP ASSOCIATE 必须走同一套凭据解析。
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

// 库的 Addr.UDPAddr() 对域名返回 nil，必须由我们把名字解析成可拨号地址。
func TestDialUDPAssociateDomainRelay(t *testing.T) {
	echo := startUDPEcho(t)
	proxy := newFakeSocks5UDPProxy(t, false, "", "")
	proxy.domainRelay = "localhost"
	np := newTestNextProxy(t, proxy.addr(), true)

	conn, err := np.DialContext(context.Background(), "udp", echo)
	if err != nil {
		t.Fatalf("DialContext(udp) with a domain relay = %v, want success", err)
	}
	defer conn.Close() //nolint:errcheck

	if _, err := conn.Write([]byte("dom")); err != nil {
		t.Fatalf("Write = %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read = %v", err)
	}
	if got := string(buf[:n]); got != "echo:dom" {
		t.Errorf("Read = %q, want %q", got, "echo:dom")
	}
}

// 两类非法目标都必须在拨号之前拦下：既然没有拨号，假代理就不该看到任何控制连接。
func TestDialUDPAssociateMalformedTarget(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"无法解析", "not-a-host-port"},
		// 库的 SerializeAddr 会把长度写成 265 mod 256 = 9，后面却跟着完整的名字。
		{"域名超过 255 字节", strings.Repeat("a", 265) + ":53"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxy := newFakeSocks5UDPProxy(t, false, "", "")
			np := newTestNextProxy(t, proxy.addr(), true)

			if _, err := np.DialContext(context.Background(), "udp", tc.target); err == nil {
				t.Fatalf("DialContext(udp) with %s = nil error, want failure", tc.name)
			}

			if proxy.waitControlClosed(200 * time.Millisecond) {
				t.Error("假代理上出现过控制连接；非法目标必须在拨号之前就被拦下")
			}
		})
	}
}

// 关联建立之后才发现的失败：上游拒绝 ASSOCIATE 时必须关掉那条控制连接，不能留在后台。
func TestDialUDPAssociateRejectedClosesControl(t *testing.T) {
	proxy := newFakeSocks5UDPProxy(t, false, "", "")
	proxy.replyCode = 0x07 // command not supported
	np := newTestNextProxy(t, proxy.addr(), true)

	if _, err := np.DialContext(context.Background(), "udp", "8.8.8.8:53"); err == nil {
		t.Fatal("DialContext(udp) = nil error, want rejection")
	}

	if !proxy.waitControlClosed(2 * time.Second) {
		t.Error("被拒绝后控制连接没有被关闭（客户端泄漏了一条连接）")
	}
}

// 库的 SerializeAddr 把域名长度截成 uint8 而不报错，这条校验必须在库之上补回来，
// 否则 >255 字节的目标会变成长度字段与实体错位的数据报。
func TestEncodeDatagramTarget(t *testing.T) {
	limit := strings.Repeat("a", 255)
	addr, err := encodeDatagramTarget(limit + ":53")
	if err != nil {
		t.Fatalf("encodeDatagramTarget(255-byte domain) = %v, want success", err)
	}
	if len(addr) != socks5.MaxAddrLen {
		t.Errorf("encoded length = %d, want %d", len(addr), socks5.MaxAddrLen)
	}

	if _, err := encodeDatagramTarget(strings.Repeat("a", 256) + ":53"); err == nil {
		t.Error("encodeDatagramTarget(256-byte domain) = nil error, want failure")
	}
	if _, err := encodeDatagramTarget("not-a-host-port"); err == nil {
		t.Error("encodeDatagramTarget(malformed) = nil error, want failure")
	}
}

func TestResolveRelayAddrRejectsInvalid(t *testing.T) {
	if _, err := resolveRelayAddr(nil, nil); err == nil {
		t.Error("resolveRelayAddr with a nil address = nil error, want failure")
	}
	if _, err := resolveRelayAddr(socks5.Addr{0x01}, nil); err == nil {
		t.Error("resolveRelayAddr with a short address = nil error, want failure")
	}
}

func TestSplitSocksAddr(t *testing.T) {
	host, port, err := splitSocksAddr(socks5.ParseAddrString("relay.example.com:1080"))
	if err != nil {
		t.Fatalf("splitSocksAddr = %v", err)
	}
	if host != "relay.example.com" || port != 1080 {
		t.Errorf("splitSocksAddr = (%q,%d), want (relay.example.com,1080)", host, port)
	}
	if _, _, err := splitSocksAddr(socks5.Addr{socks5.AtypDomainName, 200, 'x'}); err == nil {
		t.Error("splitSocksAddr with a truncated name = nil error, want failure")
	}
}

// 数据面的独立字节级断言：两侧都用 socks5 包时，只靠往返测试会让两侧一起错而测试通过，
// 因此这里比对手工拼出的期望字节。
func TestUDPAssociateConnWriteWireBytes(t *testing.T) {
	// Write 走已连接 socket，因此必须有一条连到对端的 socket；对端在另一个监听 socket 上收字节，
	// 内核不会把数据报回送给同一个 socket。
	peerListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen peer: %v", err)
	}
	defer peerListener.Close() //nolint:errcheck

	relay, err := net.DialUDP("udp4", nil, peerListener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer relay.Close() //nolint:errcheck

	server, client := net.Pipe()
	defer server.Close() //nolint:errcheck
	defer client.Close() //nolint:errcheck

	conn := &udpAssociateConn{control: server, relay: relay, dst: socks5.ParseAddrString("8.8.8.8:53")}
	defer conn.Close() //nolint:errcheck

	payload := []byte("dns-query-bytes")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write = %v", err)
	}

	if err := peerListener.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline = %v", err)
	}
	buf := make([]byte, maxUDPDatagram)
	n, _, err := peerListener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}

	want := []byte{0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35}
	want = append(want, payload...)
	if got := buf[:n]; !bytes.Equal(got, want) {
		t.Errorf("wire bytes = % x\n           want % x", got, want)
	}
}

func TestUDPAssociateConnReadVerbatimDatagram(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	defer relay.Close() //nolint:errcheck

	server, client := net.Pipe()
	defer server.Close() //nolint:errcheck
	defer client.Close() //nolint:errcheck

	conn := &udpAssociateConn{control: server, relay: relay, dst: socks5.ParseAddrString("8.8.8.8:53")}
	defer conn.Close() //nolint:errcheck

	payload := []byte("dns-answer")
	datagram := []byte{0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35}
	datagram = append(datagram, payload...)
	if _, err := relay.WriteToUDP(datagram, relay.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write datagram: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read = %v", err)
	}
	if got := buf[:n]; !bytes.Equal(got, payload) {
		t.Errorf("Read payload = %q, want %q (read %d bytes)", got, payload, n)
	}
}

// 超过档位的数据报必须丢弃并继续读下一条，而不是把前 maxUDPDatagram 字节当成完整数据报返回。
// p = udpBufSize+1 靠载荷长度判据丢弃，p = udpBufSize+100 靠截断判据（n == len(buf)）丢弃。
func TestUDPAssociateConnReadDropsTruncatedDatagram(t *testing.T) {
	if runtime.GOOS == "darwin" {
		// macOS 的 net.inet.udp.maxdgram 默认 9216，回环上发不出 16KB 数据报。
		t.Skip("macOS net.inet.udp.maxdgram defaults to 9216")
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	defer relay.Close() //nolint:errcheck

	server, client := net.Pipe()
	defer server.Close() //nolint:errcheck
	defer client.Close() //nolint:errcheck

	conn := &udpAssociateConn{control: server, relay: relay, dst: socks5.ParseAddrString("8.8.8.8:53")}
	defer conn.Close() //nolint:errcheck

	header := []byte{0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35}
	send := func(payload []byte) {
		t.Helper()
		datagram := append(append([]byte(nil), header...), payload...)
		if _, err := relay.WriteToUDP(datagram, relay.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatalf("write datagram: %v", err)
		}
	}
	send(bytes.Repeat([]byte{0xAA}, udpBufSize+1))   // 未截断，但载荷越过预算
	send(bytes.Repeat([]byte{0xBB}, udpBufSize+100)) // 整包越过档位，被截断
	want := []byte("dns-answer")
	send(want)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read = %v", err)
	}
	if got := buf[:n]; !bytes.Equal(got, want) {
		t.Fatalf("Read payload = %q, want %q（超限数据报必须被丢弃）", got, want)
	}
}

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

// 上游撤销关联后，阻塞中的 Read 必须立即返回，而不是僵死到会话空闲超时。
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

// 无法解析（这里是分片）的数据报是丢包，不是会话故障：中继循环必须继续读下一条。
func TestUDPAssociateConnDropsMalformedDatagram(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	server, client := net.Pipe()
	defer server.Close() //nolint:errcheck
	defer client.Close() //nolint:errcheck

	conn := &udpAssociateConn{control: server, relay: relay, dst: socks5.ParseAddrString("127.0.0.1:53")}
	defer conn.Close() //nolint:errcheck

	sender, err := net.DialUDP("udp", nil, relay.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer sender.Close() //nolint:errcheck

	fragmented := []byte{0, 0, 0x01, socks5.AtypIPv4, 127, 0, 0, 1, 0, 53, 'x'}
	if _, err := sender.Write(fragmented); err != nil {
		t.Fatalf("write fragmented datagram: %v", err)
	}
	valid, err := socks5.EncodeUDPPacket(socks5.ParseAddrString("127.0.0.1:53"), []byte("ok"))
	if err != nil {
		t.Fatalf("encode valid datagram: %v", err)
	}
	if _, err := sender.Write(valid); err != nil {
		t.Fatalf("write valid datagram: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read after a malformed datagram = %v", err)
	}
	if got := string(buf[:n]); got != "ok" {
		t.Fatalf("Read = %q, want the datagram following the malformed one", got)
	}
}

// 判错地址族会把 v4 地址绑给 v6 socket，让拨号失败。
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

// 同族才绑定，异构必须放弃绑定。
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
