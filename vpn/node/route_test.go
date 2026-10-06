package vpnnode

import (
	"context"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	tailcat "github.com/tailscale/tailcat"
	"github.com/things-go/go-socks5/statute"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/stats"

	vpn "github.com/nange/easyss/v3/vpn"
)

// recordingPeer 是一个"看得见内层目标"的对端：真实的 tailcat Server 加一个最小的
// SOCKS5 服务端，把每条 CONNECT 请求里的目标记下来后把数据原样回送。
//
// 为什么不用 PeerFace：它的拨号器只拒绝非 loopback，无法区分 127.0.0.1 与
// 127.0.0.2，因此"访问侧把目标归一化成字面 127.0.0.1"这条契约只能在更靠里的位置
// 断言。这里读到的就是隧道里真实传输的 CONNECT 请求。
type recordingPeer struct {
	addr string
	port int

	srv *tailcat.Server
	ln  net.Listener

	mu      sync.Mutex
	targets []string
}

func startRecordingPeer(t *testing.T, region *tailcfg.DERPRegion) *recordingPeer {
	t.Helper()

	identity, err := LoadOrCreateNodeIdentity(peerTestPath(t, "recorder-identity.json"))
	if err != nil {
		t.Fatalf("LoadOrCreateNodeIdentity: %v", err)
	}
	p := &recordingPeer{
		addr: identity.Address(region),
		port: peerTestPort(t),
		srv: &tailcat.Server{
			Key:          identity.Private,
			PresharedKey: identity.Public.PresharedKey,
			Region:       region,
			Logf:         vpn.Logf,
		},
	}
	ln, err := p.srv.Listen(context.Background(), "tcp", ":"+strconv.Itoa(p.port))
	if err != nil {
		t.Fatalf("recording peer listen: %v", err)
	}
	p.ln = ln
	t.Cleanup(func() {
		_ = ln.Close()
		_ = p.srv.Close()
	})

	go p.acceptLoop()
	return p
}

func (p *recordingPeer) acceptLoop() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.serve(conn)
	}
}

func (p *recordingPeer) serve(c net.Conn) {
	defer c.Close() //nolint:errcheck

	if _, err := statute.ParseMethodRequest(c); err != nil {
		return
	}
	if _, err := c.Write([]byte{statute.VersionSocks5, statute.MethodNoAuth}); err != nil {
		return
	}
	req, err := statute.ParseRequest(c)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, req.DstAddr.String())
	p.mu.Unlock()

	reply := statute.Reply{
		Version:  statute.VersionSocks5,
		Response: statute.RepSuccess,
		BndAddr:  statute.AddrSpec{AddrType: statute.ATYPIPv4, IP: net.IPv4zero},
	}
	if _, err := c.Write(reply.Bytes()); err != nil {
		return
	}
	_, _ = io.Copy(c, c)
}

func (p *recordingPeer) recordedTargets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

// newTestRoute 构造访问侧：一个 overlay 与一份持久的 client key。
func newTestRoute(t *testing.T, peers ...PeerRef) (*Route, *Overlay) {
	t.Helper()

	overlay, err := Assign(sharedconfig.DefaultVPNOverlayPrefix(), peers)
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	clients, err := NewClientSet(ClientSetOptions{
		KeyPath: peerTestPath(t, "client.key"),
		Peers:   peers,
	})
	if err != nil {
		t.Fatalf("NewClientSet: %v", err)
	}
	t.Cleanup(func() { _ = clients.Close() })

	route, err := NewRoute(RouteOptions{
		Overlay:  overlay,
		Clients:  clients,
		Timeouts: sharedconfig.Timeouts{Dial: 30 * time.Second, Base: 30 * time.Second},
	})
	if err != nil {
		t.Fatalf("NewRoute: %v", err)
	}
	return route, overlay
}

// TestRouteInnerTargetIsLiteralLoopback 是阶段 4 的核心验收：无论应用写的是对端名
// 还是 overlay IP，隧道里传输的 CONNECT 目标**恒为字面 127.0.0.1:<port>**。
//
// 这条契约是访问侧与对端面之间唯一的跨节点协议，也是"对端不需要知道访问侧的任何
// 配置"这一结论的全部依据（见 docs/vpn-design.md 5.1）。
func TestRouteInnerTargetIsLiteralLoopback(t *testing.T) {
	echoAddr, stopEcho := startTCPEchoLocal(t)
	defer stopEcho()
	_, echoPortStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}

	region := startTestDERP(t)
	peer := startRecordingPeer(t, region)
	route, overlay := newTestRoute(t, PeerRef{HostName: "b", Address: peer.addr, Port: peer.port})

	overlayIP, ok := overlay.Addr("b")
	if !ok {
		t.Fatal("the overlay has no address for peer b")
	}

	cases := []struct {
		name   string
		target string
	}{
		{"按对端名", net.JoinHostPort("b", echoPortStr)},
		{"按 overlay IP", net.JoinHostPort(overlayIP.String(), echoPortStr)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()

			// 记录基线：每条子用例只断言自己这次产生的 CONNECT，避免共享的对端
			// 把上一条子用例的记录带进来。
			before := len(peer.recordedTargets())

			conn, err := route.DialTCP(ctx, tc.target)
			if err != nil {
				t.Fatalf("DialTCP(%s): %v", tc.target, err)
			}
			defer conn.Close() //nolint:errcheck

			payload := []byte("hello " + tc.name)
			_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if string(got) != string(payload) {
				t.Fatalf("echo = %q, want %q", got, payload)
			}

			want := net.JoinHostPort(innerTargetHost, echoPortStr)
			recorded := peer.recordedTargets()[before:]
			if len(recorded) == 0 {
				t.Fatal("no inner CONNECT was recorded, so this case proves nothing")
			}
			for _, dst := range recorded {
				if dst != want {
					t.Fatalf("the tunnel carried %q, want exactly %q: peer names and overlay IPs must never enter the tunnel", dst, want)
				}
			}
		})
	}

	// 两种书写形式必须命中同一条逻辑对端。
	if name, ok := route.Lookup("b"); !ok || name != "b" {
		t.Fatalf("Lookup(b) = %q, %v; want b, true", name, ok)
	}
	if name, ok := route.Lookup(overlayIP.String()); !ok || name != "b" {
		t.Fatalf("Lookup(%s) = %q, %v; want b, true", overlayIP, name, ok)
	}
	if _, ok := route.Lookup("unknown"); ok {
		t.Fatal("Lookup(unknown) reported a peer")
	}
}

// TestRouteThroughPeerFace 是与真实对端面的互操作：Route 拨进 PeerFace，再经它的
// loopback-only 拨号器访问**对端本机**的服务。
func TestRouteThroughPeerFace(t *testing.T) {
	echoAddr, stopEcho := startTCPEchoLocal(t)
	defer stopEcho()
	_, echoPortStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}

	region := startTestDERP(t)
	face := newTestPeerFace(t, region)
	if err := face.Start(context.Background()); err != nil {
		t.Fatalf("PeerFace.Start: %v", err)
	}
	defer func() { _ = face.Stop() }()

	route, overlay := newTestRoute(t, PeerRef{HostName: "b", Address: face.TailcatAddr(), Port: peerTestPort(t)})
	overlayIP, _ := overlay.Addr("b")

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	conn, err := route.DialTCP(ctx, net.JoinHostPort(overlayIP.String(), echoPortStr))
	if err != nil {
		t.Fatalf("DialTCP through the peer face: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	payload := []byte("via the real peer face")
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

// TestRouteUDPThroughPeerFace 固定 UDP 路径的两半拼在一起的样子：Route 的一次性
// 目标头（targetHeaderConn）必须被对端面的 UDPRelay 正确解出，数据报双向透传。
func TestRouteUDPThroughPeerFace(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoLocal(t)
	defer stopEcho()
	_, echoPortStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}

	region := startTestDERP(t)
	face := newTestPeerFace(t, region)
	if err := face.Start(context.Background()); err != nil {
		t.Fatalf("PeerFace.Start: %v", err)
	}
	defer func() { _ = face.Stop() }()

	route, _ := newTestRoute(t, PeerRef{HostName: "b", Address: face.TailcatAddr(), Port: peerTestPort(t)})

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// 统计触点：一条成功的隧道 UDP 流必须被访问侧与对端面各计一次。
	before := stats.Collect()
	flow, err := route.DialUDP(ctx, net.JoinHostPort("b", echoPortStr))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer flow.Close() //nolint:errcheck
	if after := stats.Collect(); after.VPNUDPFlows != before.VPNUDPFlows+1 {
		t.Errorf("vpn_udp_flows = %d, want %d: a successful tunnel udp flow must be counted",
			after.VPNUDPFlows, before.VPNUDPFlows+1)
	}

	payload := []byte("udp via the real peer face")
	if _, err := flow.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := flow.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := flow.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("udp echo = %q, want %q", buf[:n], payload)
	}
}

// TestRouteRejectsBadTargets 固定访问侧的失败路径：它们都必须在拨号之前就被拦住，
// 否则错误会以隧道超时的形式出现，而不是一条能读懂的信息。
func TestRouteRejectsBadTargets(t *testing.T) {
	region := startTestDERP(t)
	peer := startRecordingPeer(t, region)
	route, _ := newTestRoute(t, PeerRef{HostName: "b", Address: peer.addr, Port: peer.port})

	ctx := context.Background()
	cases := []struct {
		name    string
		target  string
		wantErr string
	}{
		{"未知对端", "unknown:80", "is not a configured peer"},
		{"缺端口", "b", "invalid target"},
		{"非数字端口", "b:http", "not a number"},
		{"端口越界", "b:70000", "out of range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := route.DialTCP(ctx, tc.target); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("DialTCP(%q) error = %v, want it to contain %q", tc.target, err, tc.wantErr)
			}
			if _, err := route.DialUDP(ctx, tc.target); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("DialUDP(%q) error = %v, want it to contain %q", tc.target, err, tc.wantErr)
			}
		})
	}
}

// TestTargetHeaderConnPrependsOnce 固定一次性目标头的字节语义：头只插进第一条
// 数据报，且返回值是**载荷**长度——多报的字节会让上层的记账与重试逻辑错位。
func TestTargetHeaderConnPrependsOnce(t *testing.T) {
	rec := &recordingConn{}
	conn := &targetHeaderConn{Conn: rec, header: []byte{3, 'a', 'b', 'c'}}

	n, err := conn.Write([]byte("first"))
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	if n != len("first") {
		t.Fatalf("first write returned %d, want %d", n, len("first"))
	}
	if _, err := conn.Write([]byte("second")); err != nil {
		t.Fatalf("second write: %v", err)
	}

	want := [][]byte{[]byte("\x03abcfirst"), []byte("second")}
	if !slices.EqualFunc(rec.writes, want, func(a, b []byte) bool { return string(a) == string(b) }) {
		t.Fatalf("datagrams = %q, want %q", rec.writes, want)
	}
}

// recordingConn 只记录 Write，用于断言组帧；其余 net.Conn 方法由嵌入的接口提供
// （用例不会调用它们，因此保持为 nil）。
type recordingConn struct {
	net.Conn //nolint:unused // 仅为满足 net.Conn

	writes [][]byte
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

// TestClientSetKeyIsStableAndCloseIsFinal 固定访问侧身份的两条要求：跨构造稳定
// （allow_clients 白名单的前提），以及关闭之后不再建立隧道。
func TestClientSetKeyIsStableAndCloseIsFinal(t *testing.T) {
	path := peerTestPath(t, "client.key")

	first, err := NewClientSet(ClientSetOptions{KeyPath: path})
	if err != nil {
		t.Fatalf("NewClientSet: %v", err)
	}
	key1 := first.ClientKey()
	if key1.IsZero() {
		t.Fatal("the client set generated a zero key")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// 幂等。
	if err := first.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := first.clientFor("whatever"); err == nil {
		t.Fatal("a closed client set still handed out a client")
	}

	second, err := NewClientSet(ClientSetOptions{KeyPath: path})
	if err != nil {
		t.Fatalf("NewClientSet again: %v", err)
	}
	defer func() { _ = second.Close() }()
	if second.ClientKey().String() != key1.String() {
		t.Fatal("the client key changed across restarts; every peer's allow_clients entry would stop matching")
	}
}

// TestClientSetRejectsBadInput 固定构造期的失败路径：没有身份、以及写错的 peer
// 地址，都必须在启动阶段报出来，而不是等到第一次访问对端。
func TestClientSetRejectsBadInput(t *testing.T) {
	if _, err := NewClientSet(ClientSetOptions{}); err == nil {
		t.Fatal("NewClientSet accepted a set with neither a key nor a key path")
	}
	if _, err := NewClientSet(ClientSetOptions{
		Key:   key.NewNode(),
		Peers: []PeerRef{{HostName: "b", Address: "not-a-tailcat-address", Port: 6080}},
	}); err == nil {
		t.Fatal("NewClientSet accepted an unparsable peer address")
	}
}

// TestNewRouteRejectsIncompleteOptions 固定组装期的自检：缺 overlay 或 client set
// 的 Route 会在第一次使用时空指针，因此宁愿在构造期就报错。
func TestNewRouteRejectsIncompleteOptions(t *testing.T) {
	if _, err := NewRoute(RouteOptions{}); err == nil {
		t.Fatal("NewRoute accepted options without an overlay")
	}
	overlay, err := Assign(sharedconfig.DefaultVPNOverlayPrefix(), nil)
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if _, err := NewRoute(RouteOptions{Overlay: overlay}); err == nil {
		t.Fatal("NewRoute accepted options without a client set")
	}
}
