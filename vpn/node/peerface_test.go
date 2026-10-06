package vpnnode

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	tailcat "github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	sharedconfig "github.com/nange/easyss/v3/config"

	vpn "github.com/nange/easyss/v3/vpn"
)

// stubFallback 是伪装页面的最小替身：这里只关心 DERP 请求有没有被正确分流。
type stubFallback struct{}

func (stubFallback) Serve(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

// startTestDERP 启动一个**进程内**的 DERP 中继：真实的 derpserver 挂在真实 TLS
// 服务器上，走我们的 vpn.NewDERPMount 分流器。
//
// 它让对端面与访问侧的测试完全不依赖外部网络，同时仍然跑真实的 DERP 协议
// （HTTP/1.1 Upgrade over TLS）——被替换掉的只有"证书"与"公网主机名"。
func startTestDERP(t *testing.T) *tailcfg.DERPRegion {
	t.Helper()

	srv := vpn.NewDERPServer(key.NewNode())
	ts := httptest.NewTLSServer(vpn.NewDERPMount(srv.Handler(), stubFallback{}))
	t.Cleanup(func() {
		_ = srv.Close()
		ts.Close()
	})

	_, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split DERP test listener addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse DERP test listener port: %v", err)
	}

	return &tailcfg.DERPRegion{
		RegionID:   vpn.RegionID,
		RegionCode: vpn.RegionCode,
		RegionName: vpn.RegionName,
		Nodes: []*tailcfg.DERPNode{{
			Name:     vpn.DERPNodeName,
			RegionID: vpn.RegionID,
			HostName: "127.0.0.1",
			DERPPort: port,
			// 测试服务器的证书是自签的；这个字段就是 DERP 协议为这种情况准备的
			//（生产路径上我们的 region 不设它，因此证书必须真的匹配）。
			InsecureForTests: true,
		}},
	}
}

// newTestPeerFace 用一份临时身份与给定的 region 构造对端面。
func newTestPeerFace(t *testing.T, region *tailcfg.DERPRegion, allow ...key.NodePublic) *PeerFace {
	t.Helper()
	identity, err := LoadOrCreateNodeIdentity(peerTestPath(t, "node-identity.json"))
	if err != nil {
		t.Fatalf("LoadOrCreateNodeIdentity: %v", err)
	}
	face, err := NewPeerFace(PeerFaceOptions{
		Identity:     identity,
		Region:       region,
		PeerPort:     peerTestPort(t),
		AllowClients: allow,
	})
	if err != nil {
		t.Fatalf("NewPeerFace: %v", err)
	}
	return face
}

// peerTestPath 返回临时目录下的一个状态文件路径。
func peerTestPath(t *testing.T, name string) string {
	t.Helper()
	return t.TempDir() + "/" + name
}

// peerTestPort 是对端面在隧道内的监听端口。隧道里的端口不在宿主上监听，因此
// 这里可以直接用默认值而不必担心与宿主冲突。
func peerTestPort(t *testing.T) int {
	t.Helper()
	return sharedconfig.DefaultVPNPeerPort
}

// startTCPEchoLocal 启动一个把收到的数据原样回送的 TCP 服务。
func startTCPEchoLocal(t *testing.T) (string, func()) {
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
	return ln.Addr().String(), func() { ln.Close() } //nolint:errcheck
}

// startUDPEchoLocal 启动一个把收到的数据原样回送的 UDP 服务。
func startUDPEchoLocal(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}
	go func() {
		buf := make([]byte, 4096)
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
	return pc.LocalAddr().String(), func() { pc.Close() } //nolint:errcheck
}

// socks5ConnectOverTunnel 在一条隧道内的连接上完成 SOCKS5 握手与 CONNECT，返回
// 应答码（0 表示成功）。target 按 SOCKS5 的域名形式发送——这正是本项目用
// hostname 目标的方式，也是"对端面必须拒绝域名"这条契约的入口。
func socks5ConnectOverTunnel(t *testing.T, conn net.Conn, target string) byte {
	t.Helper()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		t.Fatalf("greeting reply = %v, want [5 0]", greeting)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split target %q: %v", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse target port: %v", err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write connect: %v", err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	// 读掉 BND.ADDR/BND.PORT，使后续读写直接进入数据阶段。
	switch hdr[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 6))
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 18))
	case 0x03:
		var ln [1]byte
		if _, err = io.ReadFull(conn, ln[:]); err == nil {
			_, err = io.ReadFull(conn, make([]byte, int(ln[0])+2))
		}
	}
	if err != nil {
		t.Fatalf("read bind address: %v", err)
	}
	return hdr[1]
}

// newTestTailcatClient 构造一个连到对端面的 tailcat 客户端，并把它的 printf 风格
// 日志接到本包的 debug 日志器上——否则 tailcat 会用标准库 log 直接打到测试输出。
func newTestTailcatClient(face *PeerFace, nodeKey key.NodePrivate) *tailcat.Client {
	client := tailcat.NewClient(tailcat.Addr(face.TailcatAddr()))
	client.Key = nodeKey
	client.Logf = vpn.Logf
	return client
}

// dialPeerFace 用 tailcat 客户端连到对端面，返回一条已完成 SOCKS5 握手前的
// 隧道内连接。
func dialPeerFace(t *testing.T, face *PeerFace, clientKey key.NodePrivate) net.Conn {
	t.Helper()
	client := newTestTailcatClient(face, clientKey)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := client.DialTCPPort(ctx, uint16(face.opts.PeerPort))
	if err != nil {
		t.Fatalf("DialTCPPort: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	return conn
}

// TestPeerFaceEndToEndOverTunnel 是阶段 3 的核心验收：真实 tailcat 隧道 + 内嵌
// DERP，从客户端拨进对端面，再经对端面的 SOCKS5 访问**对端本机**的一个服务。
//
// 它同时固定了 5.1 的内层 CONNECT 契约：目标必须是字面 loopback。用域名
// （这里就是 "localhost"，最容易被误当成等价物）会被对端面拒绝，因此访问侧无论如何
// 都必须把目标归一化成字面 127.0.0.1。
func TestPeerFaceEndToEndOverTunnel(t *testing.T) {
	echoAddr, stopEcho := startTCPEchoLocal(t)
	defer stopEcho()
	_, echoPort, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}

	region := startTestDERP(t)
	face := newTestPeerFace(t, region)
	if err := face.Start(context.Background()); err != nil {
		t.Fatalf("PeerFace.Start: %v", err)
	}
	defer func() { _ = face.Stop() }()

	t.Run("字面 loopback 目标可达", func(t *testing.T) {
		conn := dialPeerFace(t, face, key.NewNode())
		if code := socks5ConnectOverTunnel(t, conn, net.JoinHostPort("127.0.0.1", echoPort)); code != 0 {
			t.Fatalf("CONNECT reply code = %d, want success", code)
		}
		payload := []byte("hello through the tunnel")
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if string(got) != string(payload) {
			t.Fatalf("echo = %q, want %q", got, payload)
		}
	})

	t.Run("域名目标被拒绝", func(t *testing.T) {
		conn := dialPeerFace(t, face, key.NewNode())
		if code := socks5ConnectOverTunnel(t, conn, net.JoinHostPort("localhost", echoPort)); code == 0 {
			t.Fatal("the peer face accepted the hostname \"localhost\"; hostnames must be rejected so that the peer face can never resolve anything")
		}
	})

	t.Run("非 loopback 字面目标被拒绝", func(t *testing.T) {
		conn := dialPeerFace(t, face, key.NewNode())
		if code := socks5ConnectOverTunnel(t, conn, net.JoinHostPort("10.0.0.1", echoPort)); code == 0 {
			t.Fatal("the peer face accepted a non-loopback literal target; it would become an intranet hop")
		}
	})
}

// TestPeerFaceEndToEndUDP 固定对端面的 UDP 路径：经隧道的一条 UDP 流，用一次性
// 目标头指定本机 loopback 上的 UDP 服务，数据报双向透传。
func TestPeerFaceEndToEndUDP(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoLocal(t)
	defer stopEcho()

	region := startTestDERP(t)
	face := newTestPeerFace(t, region)
	if err := face.Start(context.Background()); err != nil {
		t.Fatalf("PeerFace.Start: %v", err)
	}
	defer func() { _ = face.Stop() }()

	client := newTestTailcatClient(face, key.NewNode())
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	flow, err := client.DialUDPPort(ctx, uint16(face.opts.PeerPort))
	if err != nil {
		t.Fatalf("DialUDPPort: %v", err)
	}
	defer func() { _ = flow.Close() }()

	header, err := EncodeUDPTarget(echoAddr)
	if err != nil {
		t.Fatalf("EncodeUDPTarget: %v", err)
	}
	payload := []byte("udp through the tunnel")
	if _, err := flow.Write(append(header, payload...)); err != nil {
		t.Fatalf("write first datagram: %v", err)
	}

	if err := flow.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := flow.Read(buf)
	if err != nil {
		t.Fatalf("read echo datagram: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("udp echo = %q, want %q", buf[:n], payload)
	}
}

// TestPeerFaceRejectsBadOptions 固定构造期的失败路径：地址必须在构造期就自检，
// 而不是等到对端第一次访问才发现。
func TestPeerFaceRejectsBadOptions(t *testing.T) {
	identity, err := LoadOrCreateNodeIdentity(peerTestPath(t, "id.json"))
	if err != nil {
		t.Fatal(err)
	}
	region, err := vpn.BuildRegion("relay.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("缺少身份", func(t *testing.T) {
		if _, err := NewPeerFace(PeerFaceOptions{Region: region, PeerPort: 6080}); err == nil {
			t.Error("NewPeerFace without an identity = nil, want error")
		}
	})
	t.Run("缺少 region", func(t *testing.T) {
		if _, err := NewPeerFace(PeerFaceOptions{Identity: identity, PeerPort: 6080}); err == nil {
			t.Error("NewPeerFace without a region = nil, want error")
		}
	})
	t.Run("peer_port 越界", func(t *testing.T) {
		for _, port := range []int{0, -1, 65536} {
			if _, err := NewPeerFace(PeerFaceOptions{Identity: identity, Region: region, PeerPort: port}); err == nil {
				t.Errorf("NewPeerFace(peer_port %d) = nil, want error", port)
			}
		}
	})
	t.Run("region 编号为零时必须拒绝", func(t *testing.T) {
		bad := &tailcfg.DERPRegion{
			RegionID: 0,
			Nodes:    []*tailcfg.DERPNode{{Name: vpn.DERPNodeName, HostName: "relay.example.com", DERPPort: 8443}},
		}
		// tailcat 在编码地址时会抹掉 region 编号、解析时按序号补成 1，因此这种
		// region 产出的地址看起来完全正常；真正会失败的是 Server.Start。
		// NewPeerFace 必须在构造期就拒绝它。
		_, err := NewPeerFace(PeerFaceOptions{Identity: identity, Region: bad, PeerPort: 6080})
		if err == nil {
			t.Fatal("NewPeerFace accepted a region with vpn.RegionID 0, want error")
		}
		if !strings.Contains(err.Error(), "RegionID 0") {
			t.Errorf("error %q should explain the vpn.RegionID 0 problem", err)
		}
	})
}

// TestPeerFaceTailcatAddrIsSelfContained 固定"对端面给出的地址可以直接给对端用"。
func TestPeerFaceTailcatAddrIsSelfContained(t *testing.T) {
	region := startTestDERP(t)
	face := newTestPeerFace(t, region)

	addr := face.TailcatAddr()
	if err := AssertFullAddr(addr); err != nil {
		t.Fatalf("TailcatAddr is not self-contained: %v", err)
	}
	parsed, err := tailcat.ParseAddr(tailcat.Addr(addr))
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	if parsed.ServerPublic.NodePublic != face.NodeKey() {
		t.Error("TailcatAddr does not advertise this node's public key")
	}
	// 地址里内嵌的 DERP 端口必须与对端实际运行的中继一致。
	if got := parsed.Region[0].Nodes[0].DERPPort; got != region.Nodes[0].DERPPort {
		t.Errorf("embedded DERPPort = %d, want %d", got, region.Nodes[0].DERPPort)
	}
}

// TestPeerFacePublishAddr 固定 peer.txt 的落盘契约：内容必须与启动日志里给出的
// 地址逐字节一致，权限 0600（地址含 preshared key，等价于接入凭据）。
func TestPeerFacePublishAddr(t *testing.T) {
	region := startTestDERP(t)
	face := newTestPeerFace(t, region)

	path := peerTestPath(t, "state/peer.txt")
	addr, err := face.PublishAddr(path)
	if err != nil {
		t.Fatalf("PublishAddr: %v", err)
	}
	if addr != face.TailcatAddr() {
		t.Error("PublishAddr returned a different address than TailcatAddr")
	}
	got, err := readFileTrimmed(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != addr {
		t.Errorf("peer.txt = %q, want %q", got, addr)
	}
	if err := AssertFullAddr(got); err != nil {
		t.Errorf("peer.txt does not contain a self-contained address: %v", err)
	}
	requirePerm(t, "peer.txt", path, 0o600)
}

// TestPeerFaceStopIsIdempotent 固定 Stop 的幂等性与"未 Start 也能 Stop"。
func TestPeerFaceStopIsIdempotent(t *testing.T) {
	region := startTestDERP(t)
	face := newTestPeerFace(t, region)

	if err := face.Stop(); err != nil {
		t.Errorf("Stop before Start: %v", err)
	}
	if err := face.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := face.Stop(); err != nil {
		t.Errorf("first Stop: %v", err)
	}
	if err := face.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

// TestPeerFaceCustomPeerPort 固定自定义 peer_port 生效：地址里内嵌的监听端口与
// 实际可拨通的端口都必须是它。
func TestPeerFaceCustomPeerPort(t *testing.T) {
	echoAddr, stopEcho := startTCPEchoLocal(t)
	defer stopEcho()
	_, echoPort, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}

	const customPort = 7001
	region := startTestDERP(t)
	identity, err := LoadOrCreateNodeIdentity(peerTestPath(t, "id.json"))
	if err != nil {
		t.Fatal(err)
	}
	face, err := NewPeerFace(PeerFaceOptions{Identity: identity, Region: region, PeerPort: customPort})
	if err != nil {
		t.Fatalf("NewPeerFace: %v", err)
	}
	if err := face.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = face.Stop() }()

	client := newTestTailcatClient(face, key.NewNode())
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := client.DialTCPPort(ctx, customPort)
	if err != nil {
		t.Fatalf("DialTCPPort(%d): %v", customPort, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	if code := socks5ConnectOverTunnel(t, conn, net.JoinHostPort("127.0.0.1", echoPort)); code != 0 {
		t.Fatalf("CONNECT reply code = %d, want success", code)
	}
	payload := []byte("custom port")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

// readFileTrimmed 读文件并去掉尾部空白。
func readFileTrimmed(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// TestPeerFaceAllowClients 固定可选的接入白名单（vpn.allow_clients）：名单内的
// client key 能连上，名单外的一律连不上。
//
// 这是"地址即凭据"之外的第二道防线：tailcat 地址本身含 preshared key，拿到地址就
// 能接入；白名单让运维可以在此之上再限制到具体的 client key。前提是访问侧的 client
// key 跨重启稳定（见 ClientKeyPath），否则白名单每次重启都会失效。
func TestPeerFaceAllowClients(t *testing.T) {
	region := startTestDERP(t)
	allowed := key.NewNode()
	denied := key.NewNode()

	face := newTestPeerFace(t, region, allowed.Public())
	if err := face.Start(context.Background()); err != nil {
		t.Fatalf("PeerFace.Start: %v", err)
	}
	defer func() { _ = face.Stop() }()

	t.Run("白名单内的 client key 可接入", func(t *testing.T) {
		client := newTestTailcatClient(face, allowed)
		defer func() { _ = client.Close() }()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := client.DialTCPPort(ctx, uint16(face.opts.PeerPort))
		if err != nil {
			t.Fatalf("DialTCPPort with an allow-listed key: %v", err)
		}
		_ = conn.Close()
	})

	t.Run("白名单外的 client key 连不上", func(t *testing.T) {
		client := newTestTailcatClient(face, denied)
		defer func() { _ = client.Close() }()

		// 被拒绝的客户端拿不到服务端的 meowed 应答，因此会一直等到 ctx 到期。
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := client.DialTCPPort(ctx, uint16(face.opts.PeerPort))
		if err == nil {
			_ = conn.Close()
			t.Fatal("DialTCPPort succeeded with a key that is not in AllowClients")
		}
	})
}
