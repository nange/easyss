package vpnnode

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestUDPTargetHeaderRoundTrip 固定一次性目标头的编解码：载荷必须原样保留，
// 目标必须是字面 loopback。
func TestUDPTargetHeaderRoundTrip(t *testing.T) {
	for _, target := range []string{"127.0.0.1:53", "127.0.0.1:65535", "127.0.0.2:6080", "[::1]:8080"} {
		header, err := EncodeUDPTarget(target)
		if err != nil {
			t.Fatalf("EncodeUDPTarget(%q): %v", target, err)
		}
		payload := []byte("payload bytes")
		pkt := append(append([]byte{}, header...), payload...)

		gotTarget, gotPayload, err := DecodeUDPTarget(pkt)
		if err != nil {
			t.Fatalf("DecodeUDPTarget: %v", err)
		}
		if gotTarget != target {
			t.Errorf("target = %q, want %q", gotTarget, target)
		}
		if string(gotPayload) != string(payload) {
			t.Errorf("payload = %q, want %q", gotPayload, payload)
		}
	}
}

// TestUDPTargetHeaderRejectsNonLoopback 固定对端面的安全边界：这个头是隧道里唯一
// 声明目标的地方，非 loopback 必须在解码阶段就被拒绝——服务端绝不能凭隧道里的
// 一句话去打内网（见 docs/vpn-design.md 5.1、第 7 节）。
func TestUDPTargetHeaderRejectsNonLoopback(t *testing.T) {
	t.Run("编码阶段", func(t *testing.T) {
		for _, target := range []string{
			"10.0.0.1:53", "192.168.1.1:80", "8.8.8.8:53", "example.com:53", "localhost:53",
			"127.0.0.1", ":53", "127.0.0.1:",
		} {
			if _, err := EncodeUDPTarget(target); err == nil {
				t.Errorf("EncodeUDPTarget(%q) = nil, want error", target)
			}
		}
	})

	t.Run("解码阶段", func(t *testing.T) {
		cases := []struct {
			name string
			pkt  []byte
		}{
			{"空数据报", nil},
			{"缺少目标头", []byte{0x00, 0x01}},
			{"头被截断", append([]byte{0x0f}, []byte("127.0.0.1")...)},
			{"域名目标", append([]byte{0x0d}, []byte("localhost:53")...)},
			{"内网目标", append([]byte{0x08}, []byte("10.0.0.1")...)},
			{"非 loopback", append([]byte{0x0b}, []byte("8.8.8.8:53")...)},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if _, _, err := DecodeUDPTarget(tc.pkt); err == nil {
					t.Errorf("DecodeUDPTarget(%v) = nil, want error", tc.pkt)
				}
			})
		}
	})

	t.Run("非 loopback 的错误信息说明原因", func(t *testing.T) {
		_, _, err := DecodeUDPTarget(append([]byte{0x0a}, []byte("8.8.8.8:53")...))
		if err == nil || !strings.Contains(err.Error(), "non-loopback") {
			t.Errorf("error = %v, want a non-loopback rejection", err)
		}
	})
}

// closeSignalConn 是"隧道侧"连接的包装，用于观察中继是否关掉了这条流。
type closeSignalConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func newCloseSignalConn(c net.Conn) *closeSignalConn {
	return &closeSignalConn{Conn: c, closed: make(chan struct{})}
}

func (c *closeSignalConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// fakeListener 只交付一条预先建好的连接，其后阻塞直到 Close。
type fakeListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newFakeListener(conn net.Conn) *fakeListener {
	return &fakeListener{conn: conn, done: make(chan struct{})}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	var out net.Conn
	l.once.Do(func() { out = l.conn })
	if out != nil {
		return out, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *fakeListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *fakeListener) Addr() net.Addr { return l.conn.LocalAddr() }

// connectedUDP 把未连接的 UDP socket 包装成"只与固定对端收发"的 net.Conn。
// Go 只对 DialUDP 出来的 socket 提供 Connect，而这里需要先拿到两端的地址。
type connectedUDP struct {
	*net.UDPConn
	peer *net.UDPAddr
}

func (c *connectedUDP) Read(b []byte) (int, error) {
	n, _, err := c.ReadFromUDP(b)
	return n, err
}

func (c *connectedUDP) Write(b []byte) (int, error) { return c.WriteToUDP(b, c.peer) }

func (c *connectedUDP) RemoteAddr() net.Addr { return c.peer }

// udpPair 返回一对互指对方的 UDP 端点：写一端，另一端可读到。
// 它充当测试里的"隧道"——真实的隧道 UDP 流同样是一次读写一个数据报的语义。
func udpPair(t *testing.T) (tunnelSide, accessSide net.Conn) {
	t.Helper()
	open := func() *net.UDPConn {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		return c
	}
	a, b := open(), open()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return &connectedUDP{UDPConn: a, peer: b.LocalAddr().(*net.UDPAddr)},
		&connectedUDP{UDPConn: b, peer: a.LocalAddr().(*net.UDPAddr)}
}

// startRelay 让中继在给定的"隧道"连接上服务一条流，返回该连接与中继。
func startRelay(t *testing.T, idle time.Duration) (*UDPRelay, *closeSignalConn, net.Conn) {
	t.Helper()
	tunnelSide, accessSide := udpPair(t)
	conn := newCloseSignalConn(tunnelSide)

	relay := &UDPRelay{IdleTimeout: idle, Logf: func(string, ...any) {}}
	ln := newFakeListener(conn)
	serveDone := make(chan error, 1)
	go func() { serveDone <- relay.Serve(ln) }()

	t.Cleanup(func() {
		_ = ln.Close()
		relay.Close()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("UDPRelay.Serve did not return")
		}
	})
	return relay, conn, accessSide
}

// TestUDPRelayForwardsDatagrams 固定中继的正向路径：第一个数据报带目标头并顺带
// 首段载荷，其后是纯数据报，回声原样回到访问侧。
func TestUDPRelayForwardsDatagrams(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoLocal(t)
	defer stopEcho()

	_, conn, access := startRelay(t, time.Minute)

	header, err := EncodeUDPTarget(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("first")
	if _, err := access.Write(append(header, first...)); err != nil {
		t.Fatalf("write first datagram: %v", err)
	}

	_ = access.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := access.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf[:n]) != string(first) {
		t.Fatalf("echo = %q, want %q", buf[:n], first)
	}

	// 后续数据报不再带目标头。
	second := []byte("second")
	if _, err := access.Write(second); err != nil {
		t.Fatalf("write second datagram: %v", err)
	}
	n, err = access.Read(buf)
	if err != nil {
		t.Fatalf("read second echo: %v", err)
	}
	if string(buf[:n]) != string(second) {
		t.Fatalf("echo = %q, want %q", buf[:n], second)
	}

	// 有流量往来时流不该被回收。
	select {
	case <-conn.closed:
		t.Fatal("the relay closed an active flow")
	default:
	}
}

// TestUDPRelayRejectsNonLoopbackTarget 固定隧道里声明内网目标时整条流被拒绝：
// 对端面绝不能凭隧道里的一句话去打内网。
func TestUDPRelayRejectsNonLoopbackTarget(t *testing.T) {
	_, conn, access := startRelay(t, time.Minute)

	pkt := append([]byte{0x0a}, []byte("8.8.8.8:53")...)
	pkt = append(pkt, []byte("payload")...)
	if _, err := access.Write(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}

	// 流应当被拆掉，而不是继续等待更多数据报。
	select {
	case <-conn.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay kept a flow whose target was rejected")
	}
}

// TestUDPRelayIdleTimeout 固定空闲回收：没有任何数据往来时，流在 IdleTimeout
// 之后被拆掉，不会永久占着一个本地套接字。
func TestUDPRelayIdleTimeout(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoLocal(t)
	defer stopEcho()

	const idle = 300 * time.Millisecond
	_, conn, access := startRelay(t, idle)

	header, err := EncodeUDPTarget(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.Write(append(header, []byte("ping")...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = access.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	if _, err := access.Read(buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	select {
	case <-conn.closed:
	case <-time.After(5 * time.Second):
		t.Fatalf("the flow was not reclaimed after the %v idle timeout", idle)
	}
}

// TestUDPRelayCloseIsPromptWithActiveFlow 是一条回归测试：曾经 Serve 在监听器关闭
// 时自己等待在飞流，而关掉那些流的 Close 要等 Serve 返回之后才被调用——于是 Stop
// 会一直卡到空闲超时（实测 2 分钟）。正确行为是毫秒级返回。
func TestUDPRelayCloseIsPromptWithActiveFlow(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoLocal(t)
	defer stopEcho()

	// 空闲上限设得很长：如果关闭路径还会等它，这个测试就会超时失败。
	relay, _, access := startRelay(t, 10*time.Minute)

	header, err := EncodeUDPTarget(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.Write(append(header, []byte("ping")...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = access.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	if _, err := access.Read(buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	done := make(chan struct{})
	go func() {
		relay.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("UDPRelay.Close blocked while a flow was active; it must close the flow sockets before waiting")
	}
}

// TestLoopbackDialContext 固定对端面拨号器的两种结局：字面 loopback 可拨通，
// 其余一律被拒（且错误信息说明原因）。
func TestLoopbackDialContext(t *testing.T) {
	echoAddr, stopEcho := startTCPEchoLocal(t)
	defer stopEcho()

	conn, err := LoopbackDialContext(t.Context(), "tcp", echoAddr)
	if err != nil {
		t.Fatalf("LoopbackDialContext(%q): %v", echoAddr, err)
	}
	defer func() { _ = conn.Close() }()

	payload := []byte("hello")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := conn.Read(got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

// TestLoopbackDialContextRejects 覆盖"绝不能拨"的目标集合。
func TestLoopbackDialContextRejects(t *testing.T) {
	cases := []struct {
		name   string
		target string
		want   string
	}{
		{"域名", "example.com:80", "literal loopback"},
		{"localhost", "localhost:80", "literal loopback"},
		{"内网地址", "10.0.0.1:80", "non-loopback"},
		{"公网地址", "8.8.8.8:53", "non-loopback"},
		{"链路本地", "169.254.1.1:80", "non-loopback"},
		{"Tailscale 段", "100.64.0.1:80", "non-loopback"},
		{"缺少端口", "127.0.0.1", "rejected target"},
		{"端口非数字", "127.0.0.1:http", "rejected target"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := LoopbackDialContext(t.Context(), "tcp", tc.target)
			if err == nil {
				_ = conn.Close()
				t.Fatalf("LoopbackDialContext(%q) = nil error, want rejection", tc.target)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should contain %q", err, tc.want)
			}
		})
	}
}

// TestLoopbackIPAcceptsAllLoopbackForms 固定 loopback 的判定覆盖整个 127.0.0.0/8
// 与 ::1，而不仅仅是 127.0.0.1：访问侧可能拨 127.0.0.2 之类的地址，它们同样只指向
// 本机。
func TestLoopbackIPAcceptsAllLoopbackForms(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "127.0.0.2", "127.255.255.254", "::1"} {
		if _, err := loopbackIP(host); err != nil {
			t.Errorf("loopbackIP(%q) = %v, want loopback", host, err)
		}
	}
	for _, host := range []string{"0.0.0.0", "::", "126.255.255.255", "128.0.0.0", "fe80::1", "::ffff:8.8.8.8"} {
		if _, err := loopbackIP(host); err == nil {
			t.Errorf("loopbackIP(%q) = nil error, want rejection", host)
		}
	}
	// 4-in-6 形式的 loopback 必须先 Unmap 再判定。
	if _, err := loopbackIP("::ffff:127.0.0.1"); err != nil {
		t.Errorf("loopbackIP(::ffff:127.0.0.1) = %v, want loopback after unmapping", err)
	}
}

// TestEncodeUDPTargetTooLong 固定长度上限：目标头只有 1 字节长度，超长目标必须
// 报错而不是静默截断（截断会让对端拨到一个完全不同的地址）。
func TestEncodeUDPTargetTooLong(t *testing.T) {
	long := "127.0.0.1:" + strings.Repeat("9", 300)
	_, err := EncodeUDPTarget(long)
	if err == nil {
		t.Fatal("EncodeUDPTarget accepted an over-long target, want error")
	}
	if errors.Is(err, net.ErrClosed) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestFlowActivity 固定"整条流空闲"的判定口径：任一方向有数据就刷新。
func TestFlowActivity(t *testing.T) {
	a := &flowActivity{}
	a.touch()
	if a.expired(time.Minute) {
		t.Error("a freshly touched flow reported expired")
	}

	time.Sleep(20 * time.Millisecond)
	if a.expired(time.Minute) {
		t.Error("a flow idle for 20ms reported expired with a 1-minute budget")
	}
	if !a.expired(10 * time.Millisecond) {
		t.Error("a flow idle for 20ms reported alive with a 10ms budget")
	}

	a.touch()
	if a.expired(10 * time.Millisecond) {
		t.Error("touch must refresh the idle timer")
	}
}
