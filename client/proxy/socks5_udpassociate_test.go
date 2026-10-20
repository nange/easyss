package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
)

// TestSocks5UDPAssociateRelaysDatagram 固定端到端 UDP ASSOCIATE：BND 地址必须真实可中继、
// 回声按客户端请求的目标地址组帧、控制连接断开后中继 socket 必须释放。路由固定 direct，不依赖隧道。
func TestSocks5UDPAssociateRelaysDatagram(t *testing.T) {
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

	frame, raw := buildUDPFrame(t, echoAddr, []byte("ping"))
	_ = frame // 帧头仅用于构造目标地址，载荷是 raw
	if _, err := client.Write(raw); err != nil {
		t.Fatalf("write datagram: %v", err)
	}

	// 回声必须按客户端请求时的目标地址组帧送回。
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read relayed reply: %v", err)
	}
	gotTarget, gotData := parseUDPFrame(t, buf[:n])
	if gotTarget != echoAddr {
		t.Errorf("reply target = %s, want %s (must be framed with the client's own target)", gotTarget, echoAddr)
	}
	if string(gotData) != "ping" {
		t.Errorf("reply payload = %q, want %q", gotData, "ping")
	}

	// 控制连接断开后中继 socket 必须被释放：向它发数据报不应再得到回声。
	if err := ctrl.Close(); err != nil {
		t.Fatalf("close control conn: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && srv.udpRelayCount() > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if n := srv.udpRelayCount(); n != 0 {
		t.Errorf("UDP relay sockets were not released after the control connection closed (%d left)", n)
	}
}

func startUDPEcho(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String(), func() {
		close(done)
		pc.Close() //nolint:errcheck
	}
}

// newTestSocks5ServerWithRouter 构造走本地直连的 Socks5Server，不接隧道传输层。
func newTestSocks5ServerWithRouter(t *testing.T, addr string, rt *router.Router) *Socks5Server {
	t.Helper()
	srv, err := NewSocks5Server(Socks5Options{
		ListenAddr: addr,
		Router:     rt,
		Timeouts:   config.Timeouts{Dial: 2 * time.Second, UDPIdle: 5 * time.Second, StreamIdle: 2 * time.Second},
	})
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	return srv
}

// socks5Associate 完成无认证握手并发起 ASSOCIATE，返回控制连接（关闭即终止关联）与通告的中继地址。
func socks5Associate(t *testing.T, socksAddr string) (net.Conn, *net.UDPAddr) {
	t.Helper()

	ctrl, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	t.Cleanup(func() { ctrl.Close() }) //nolint:errcheck
	_ = ctrl.SetDeadline(time.Now().Add(10 * time.Second))

	// 握手：只提供"无认证"。
	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, greeting); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		t.Fatalf("greeting reply = %v, want [5 0]", greeting)
	}

	// ASSOCIATE，目标 0.0.0.0:0（客户端不预告自己的 UDP 端点）。
	if _, err := ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write associate: %v", err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, hdr); err != nil {
		t.Fatalf("read associate reply header: %v", err)
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		t.Fatalf("associate reply = %v, want success (0x00)", hdr)
	}

	var relayIP net.IP
	var addrLen int
	switch hdr[3] {
	case 0x01:
		relayIP, addrLen = make(net.IP, 4), 4
	case 0x04:
		relayIP, addrLen = make(net.IP, 16), 16
	default:
		t.Fatalf("unexpected bind atyp %d", hdr[3])
	}
	if _, err := io.ReadFull(ctrl, relayIP); err != nil {
		t.Fatalf("read bind address (%d bytes): %v", addrLen, err)
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(ctrl, portBuf[:]); err != nil {
		t.Fatalf("read bind port: %v", err)
	}
	relayAddr := &net.UDPAddr{IP: relayIP, Port: int(binary.BigEndian.Uint16(portBuf[:]))}
	if relayAddr.Port == 0 {
		t.Fatal("associate reply advertised port 0")
	}
	return ctrl, relayAddr
}

// TestSocks5UDPAssociateDropsFragmentedDatagram 固定 FRAG 门控：本项目不做 SOCKS5 数据报
// 重组，FRAG != 0 的数据报必须丢弃，不能把残缺分片当完整载荷中继出去。
func TestSocks5UDPAssociateDropsFragmentedDatagram(t *testing.T) {
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

	// 与正常帧完全相同的组帧，只把 FRAG（第 3 字节）改成非零。
	_, raw := buildUDPFrame(t, echoAddr, []byte("ping"))
	raw[2] = 0x01
	if _, err := client.Write(raw); err != nil {
		t.Fatalf("write fragmented datagram: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 2048)
	if n, err := client.Read(buf); err == nil {
		t.Fatalf("fragmented datagram was relayed (%d bytes); it must be dropped", n)
	}
}

// TestSocks5UDPAssociateConcurrent 固定并发 ASSOCIATE：每个关联必须拿到自己可用的中继端口。
//
// 这是 TUN 模式的常态：tun2socks 为每条 UDP 流单独发起一次 ASSOCIATE，第二条若绑到固定端口就 EADDRINUSE。
func TestSocks5UDPAssociateConcurrent(t *testing.T) {
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

	const n = 3
	relays := make([]*net.UDPAddr, 0, n)
	for i := range n {
		ctrl, relayAddr := socks5Associate(t, srv.listenAddr)
		defer ctrl.Close() //nolint:errcheck
		relays = append(relays, relayAddr)

		// 每个关联都必须真正能中继。
		client, err := net.DialUDP("udp", nil, relayAddr)
		if err != nil {
			t.Fatalf("association #%d: dial relay udp: %v", i, err)
		}
		_, raw := buildUDPFrame(t, echoAddr, []byte("ping"))
		if _, err := client.Write(raw); err != nil {
			client.Close() //nolint:errcheck
			t.Fatalf("association #%d: write datagram: %v", i, err)
		}
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		if _, err := client.Read(buf); err != nil {
			client.Close() //nolint:errcheck
			t.Fatalf("association #%d (relay %s): no relayed reply: %v", i, relayAddr, err)
		}
		client.Close() //nolint:errcheck
	}

	for i := range relays {
		for j := i + 1; j < len(relays); j++ {
			if relays[i].Port == relays[j].Port {
				t.Errorf("associations #%d and #%d share relay port %d", i, j, relays[i].Port)
			}
		}
	}
}

func startTCPEcho(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp echo: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close() //nolint:errcheck
	}
}

// TestSocks5PipelinedConnectPayload 固定流水线 CONNECT：与握手、CONNECT 合并在一次写入里的
// 首批载荷必须被完整中继。握手走 bufio.Reader，缓冲里剩下的载荷若被业务层直接从裸连接读走就会静默丢失。
func TestSocks5PipelinedConnectPayload(t *testing.T) {
	echoAddr, stopEcho := startTCPEcho(t)
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

	host, portStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatalf("split echo addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse echo port: %v", err)
	}

	payload := []byte("early-data")
	greeting := []byte{0x05, 0x01, 0x00}
	connect := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	connect = append(connect, host...)
	connect = append(connect, byte(port>>8), byte(port))
	buf := append(append(append([]byte{}, greeting...), connect...), payload...)

	conn, err := net.Dial("tcp", srv.listenAddr)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("single-shot write: %v", err)
	}

	// 先读握手应答（VER + METHOD），再读 CONNECT 应答
	// （VER + REP + RSV + ATYP=IPv4 + 0.0.0.0:0），最后才是被回送的载荷。
	greetingReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetingReply); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if greetingReply[0] != 0x05 || greetingReply[1] != 0x00 {
		t.Fatalf("greeting reply = %v, want [5 0]", greetingReply)
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("connect reply = %v, want success", reply[:2])
	}

	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatalf("read echoed early data: %v (the pipelined payload was dropped)", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Errorf("echoed = %q, want %q", echoed, payload)
	}
}

// TestSocks5FailureReplyUsesIPv4 固定失败应答一律用 IPv4 零地址：RFC 1928 要求客户端忽略
// 失败应答里的 BND.ADDR/BND.PORT，所以这与按请求地址族回应答等价，固化下来防止被静默改回。
func TestSocks5FailureReplyUsesIPv4(t *testing.T) {
	var buf bytes.Buffer

	for _, reply := range []uint8{repNotAllowed, repHostUnreachable, repServerFailure} {
		buf.Reset()
		if err := writeSocksReply(&buf, reply, &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}); err != nil {
			t.Fatalf("writeSocksReply(%#x): %v", reply, err)
		}
		got := buf.Bytes()
		if len(got) != 10 {
			t.Fatalf("reply %#x length = %d, want 10 (IPv4 zero address)", reply, len(got))
		}
		if got[0] != 0x05 || got[1] != reply || got[3] != 0x01 {
			t.Errorf("reply %#x = %v, want VER=5 REP=%#x ATYP=0x01", reply, got[:4], reply)
		}
		if !bytes.Equal(got[4:8], []byte{0, 0, 0, 0}) {
			t.Errorf("reply %#x bind addr = %v, want 0.0.0.0", reply, got[4:8])
		}
	}

	// 成功应答仍然自适应地址族：IPv6 绑定地址必须以 ATYP=0x04 通告。
	buf.Reset()
	if err := writeSocksReply(&buf, repSuccess, &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}); err != nil {
		t.Fatalf("writeSocksReply(success): %v", err)
	}
	got := buf.Bytes()
	if got[3] != 0x04 {
		t.Errorf("success reply ATYP = %#x, want 0x04 for an IPv6 bind address", got[3])
	}
	if len(got) != 22 {
		t.Errorf("success reply length = %d, want 22", len(got))
	}
}

// TestSocks5UDPAssociateSurvivesOtherAssociations 固定多个关联长期共存：新关联建立后更早的
// 关联必须仍可用。每关联一个 socket 时，若新关联去关掉上一个，并发 UDP 流就只剩最新一条能活。
func TestSocks5UDPAssociateSurvivesOtherAssociations(t *testing.T) {
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

	ctrlA, relayA := socks5Associate(t, srv.listenAddr)
	defer ctrlA.Close() //nolint:errcheck
	clientA, err := net.DialUDP("udp", nil, relayA)
	if err != nil {
		t.Fatalf("dial relay A: %v", err)
	}
	defer clientA.Close() //nolint:errcheck

	ctrlB, relayB := socks5Associate(t, srv.listenAddr)
	defer ctrlB.Close() //nolint:errcheck
	clientB, err := net.DialUDP("udp", nil, relayB)
	if err != nil {
		t.Fatalf("dial relay B: %v", err)
	}
	defer clientB.Close() //nolint:errcheck

	if relayA.Port == relayB.Port {
		t.Fatalf("associations share relay port %d", relayA.Port)
	}

	relayThrough := func(name string, client *net.UDPConn, payload string) {
		t.Helper()
		_, raw := buildUDPFrame(t, echoAddr, []byte(payload))
		if _, err := client.Write(raw); err != nil {
			t.Fatalf("%s: write through relay: %v", name, err)
		}
		if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("%s: set read deadline: %v", name, err)
		}
		buf := make([]byte, 2048)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("%s: no relayed reply (relay was killed by a later association?): %v", name, err)
		}
		_, data := parseUDPFrame(t, buf[:n])
		if string(data) != payload {
			t.Errorf("%s: payload = %q, want %q", name, data, payload)
		}
	}

	// B 建立之后再回测 A：这才是"新关联不得杀死旧关联"的断言点。
	relayThrough("A after B was created", clientA, "ping-a")
	relayThrough("B", clientB, "ping-b")
	// 再建一个 C，A 仍须存活（持续可用，而不是只扛住一次替换）。
	ctrlC, relayC := socks5Associate(t, srv.listenAddr)
	defer ctrlC.Close() //nolint:errcheck
	if relayC.Port == relayA.Port || relayC.Port == relayB.Port {
		t.Fatalf("association C reused relay port %d", relayC.Port)
	}
	relayThrough("A after C was created", clientA, "ping-a2")
	relayThrough("B after C was created", clientB, "ping-b2")

	// 一个关联的控制连接断开，只应回收它自己的中继，不得影响其他关联。
	if err := ctrlB.Close(); err != nil {
		t.Fatalf("close control B: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && srv.udpRelayCount() > 2 {
		time.Sleep(20 * time.Millisecond)
	}
	relayThrough("A after B's control connection closed", clientA, "ping-a3")
}

// TestTCPHalfClosePropagatesToClient 固定远端→客户端方向的半关闭传播：远端写完关闭后客户端的
// Read 必须立刻看到 EOF。copyHalfClose（route.go）对 socks5Stream 做 CloseWrite 鸭子断言，不转发 FIN 就只剩秒级空闲超时。
func TestTCPHalfClosePropagatesToClient(t *testing.T) {
	// 只回送一条消息就关闭写侧的远端：它的 FIN 必须被传播给客户端。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil && n == 0 {
			return
		}
		if _, err := conn.Write([]byte("remote-reply")); err != nil {
			return
		}
		// 优雅半关闭写侧；连接保持打开。
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		time.Sleep(2 * time.Second)
	}()

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

	conn := socks5HandshakeConnectRaw(t, srv.listenAddr, ln.Addr().String())
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	reply := make([]byte, len("remote-reply"))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(reply) != "remote-reply" {
		t.Fatalf("reply = %q", reply)
	}

	// 远端的 FIN 必须立即传到这里：给一个远小于空闲超时的预算。
	start := time.Now()
	if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, err = conn.Read(make([]byte, 16))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected EOF after the remote half-closed")
	}
	if elapsed >= time.Second {
		t.Fatalf("EOF took %v: the remote FIN was not propagated (client waited for the idle timeout)", elapsed)
	}
}

// socks5HandshakeConnectRaw 完成握手与 CONNECT，返回底层 *net.TCPConn 以便调用方 CloseWrite。
func socks5HandshakeConnectRaw(t *testing.T, socksAddr, target string) *net.TCPConn {
	t.Helper()

	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		t.Fatalf("greeting reply = %v, want [5 0]", greeting)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split target: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write connect: %v", err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if hdr[1] != 0x00 {
		t.Fatalf("connect reply = %v, want success", hdr)
	}
	switch hdr[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 6))
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 18))
	case 0x03:
		var ln [1]byte
		if _, err = io.ReadFull(conn, ln[:]); err != nil {
			t.Fatalf("read bind domain length: %v", err)
		}
		_, err = io.ReadFull(conn, make([]byte, int(ln[0])+2))
	default:
		t.Fatalf("unexpected bind atyp %d", hdr[3])
	}
	if err != nil {
		t.Fatalf("read bind address: %v", err)
	}

	_ = conn.SetDeadline(time.Time{})
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("expected *net.TCPConn, got %T", conn)
	}
	return tcp
}
