package vpnnode

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	tailcat "github.com/tailscale/tailcat"
	"tailscale.com/envknob"
	"tailscale.com/types/key"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/stats"

	vpn "github.com/nange/easyss/v3/vpn"
)

// recordingDERPMapCache 记录对 tailcat DERP map 缓存的任何访问。
//
// 它是"零官方 DERPMap 请求"的判据：peer 地址是完整展开格式时，`ConnInfo.Expand`
// 直接返回，**根本不会走到 DERP map 来源**；一旦地址退化成短格式，Expand 会先查
// 缓存（再回退到 `https://tailcat.dev/derpmap.json`）——这一次查询就是我们要拦住的
// 信号。官方 URL 是常量（无法在测试里替换），因此缓存访问是等价的、可观测的证据。
type recordingDERPMapCache struct {
	mu   sync.Mutex
	gets int
	puts int
}

func (c *recordingDERPMapCache) Get(string) (data []byte, etag string, storedAt time.Time, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets++
	return nil, "", time.Time{}, false
}

func (c *recordingDERPMapCache) Put(string, []byte, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.puts++
	return nil
}

func (c *recordingDERPMapCache) accesses() (gets, puts int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gets, c.puts
}

// newAccessSide 按与 runner.startVPN 相同的顺序组装访问侧（overlay → ClientSet →
// Route），并使用给定的 client key——白名单必须与它是同一份。
func newAccessSide(t *testing.T, face *PeerFace, clientKey key.NodePrivate, cache tailcat.DERPMapCache) (*Route, *ClientSet) {
	t.Helper()

	ref := PeerRef{HostName: "b", Address: face.TailcatAddr(), Port: face.opts.PeerPort}
	clients, err := NewClientSet(ClientSetOptions{
		Key:          clientKey,
		Peers:        []PeerRef{ref},
		DERPMapCache: cache,
	})
	if err != nil {
		t.Fatalf("NewClientSet: %v", err)
	}
	t.Cleanup(func() { _ = clients.Close() })

	overlay, err := Assign(sharedconfig.DefaultVPNOverlayPrefix(), []PeerRef{ref})
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	route, err := NewRoute(RouteOptions{
		Overlay:  overlay,
		Clients:  clients,
		Timeouts: sharedconfig.Timeouts{Dial: 40 * time.Second, Base: 30 * time.Second},
	})
	if err != nil {
		t.Fatalf("NewRoute: %v", err)
	}
	return route, clients
}

// dialEchoTCP 经访问侧打开一条到对端本机 echo 服务的连接并做一次往返。
func dialEchoTCP(t *testing.T, route *Route, port string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	conn, err := route.DialTCP(ctx, net.JoinHostPort("b", port))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close() //nolint:errcheck

	payload := []byte("phase 5 end to end")
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

// TestVPNNodeEndToEndNeverFetchesTheOfficialDERPMap 是阶段 5 的端到端验收：进程内
// DERP 中继 + 真实 tailcat 隧道 + 对端面 + 访问侧，全部按生产路径组装。
//
// 同时断言"零官方 DERPMap 请求"（见 recordingDERPMapCache）与 `allow_clients`
// 白名单可用（对端面只接受 ClientSet 从 `<exe>/vpn/client.key` 读出来的那把 key）。
func TestVPNNodeEndToEndNeverFetchesTheOfficialDERPMap(t *testing.T) {
	echoAddr, stopEcho := startTCPEchoLocal(t)
	defer stopEcho()
	_, echoPort, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}

	region := startTestDERP(t)
	// 生产路径上这把 key 来自 <exe>/vpn/client.key，由 ClientSet 自己读取/生成。
	clientKey, err := vpn.LoadOrCreateKey(peerTestPath(t, "client.key"))
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}

	face := newTestPeerFace(t, region, clientKey.Public())
	if err := face.Start(context.Background()); err != nil {
		t.Fatalf("PeerFace.Start: %v", err)
	}
	defer func() { _ = face.Stop() }()

	cache := &recordingDERPMapCache{}
	route, _ := newAccessSide(t, face, clientKey, cache)

	// 统计计数器的触点也在这里被固定：一次成功的对端拨号必须同时被访问侧
	// （vpn_tcp_streams）与对端面（vpn_peer_face_streams）计到，而且不能记成失败。
	before := stats.Collect()
	dialEchoTCP(t, route, echoPort)
	after := stats.Collect()
	if after.VPNTCPStreams != before.VPNTCPStreams+1 {
		t.Errorf("vpn_tcp_streams = %d, want %d: a successful peer dial must be counted exactly once",
			after.VPNTCPStreams, before.VPNTCPStreams+1)
	}
	if after.VPNPeerFaceStreams != before.VPNPeerFaceStreams+1 {
		t.Errorf("vpn_peer_face_streams = %d, want %d: the peer face accepted a stream but did not count it",
			after.VPNPeerFaceStreams, before.VPNPeerFaceStreams+1)
	}
	if after.VPNDialErrors != before.VPNDialErrors {
		t.Errorf("vpn_dial_errors grew from %d to %d although the dial succeeded",
			before.VPNDialErrors, after.VPNDialErrors)
	}

	if gets, puts := cache.accesses(); gets != 0 || puts != 0 {
		t.Fatalf("tailcat consulted the DERP map cache (get=%d, put=%d): the peer address is not fully expanded, "+
			"so this node would fetch %s", gets, puts, tailcat.DefaultDERPMapURL)
	}
}

// TestVPNNodeRelayOnlyUsesTheRelay 固定 relay_only 的行为后果：隧道仍然可用，但
// **没有任何直连路径**。
//
// "无直连"正是这个开关的定义（magicsock 绑 newBlockForeverConn，完全不创建 UDP
// socket，见 docs/vpn-design.md 8.1）。这里用 DiscoPing 观测：它会主动触发一次直连
// 路径发现，因此如果 UDP 出口存在，Endpoint 有机会被填上；开了开关则必然为空。
func TestVPNNodeRelayOnlyUsesTheRelay(t *testing.T) {
	// 必须在任何 tailcat Server/Client 启动之前生效。
	ApplyRelayOnly(true)
	t.Cleanup(func() { ApplyRelayOnly(false) })
	if !envknob.Bool(RelayOnlyEnvKnob) {
		t.Fatalf("%s was not set", RelayOnlyEnvKnob)
	}

	echoAddr, stopEcho := startTCPEchoLocal(t)
	defer stopEcho()
	_, echoPort, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}

	region := startTestDERP(t)
	clientKey, err := vpn.LoadOrCreateKey(peerTestPath(t, "client.key"))
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	face := newTestPeerFace(t, region, clientKey.Public())
	if err := face.Start(context.Background()); err != nil {
		t.Fatalf("PeerFace.Start: %v", err)
	}
	defer func() { _ = face.Stop() }()

	route, clients := newAccessSide(t, face, clientKey, nil)

	// 隧道本身必须照常工作：强制中继不能以"连不上"为代价。
	dialEchoTCP(t, route, echoPort)

	client, err := clients.clientFor(face.TailcatAddr())
	if err != nil {
		t.Fatalf("clientFor: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	path, err := PathStatus(ctx, client)
	if err != nil {
		t.Fatalf("PathStatus: %v", err)
	}
	if path.Direct {
		t.Fatalf("relay_only is on but the tunnel reported a direct path %q: an UDP socket exists, "+
			"which under TUN would loop back into easyss", path.Endpoint)
	}
	// 编号在访问侧看到的是 1 而不是 vpn.RegionID，见
	// TestPeerAddressRegionNumberIsRewritten。这里只断言"确实经中继"。
	if path.DERPRegionID == 0 {
		t.Fatalf("PathStatus reported neither a relay nor a direct path: %+v", path)
	}
}

// TestPeerAddressRegionNumberIsRewritten 固定 tailcat 地址往返的一个易被误读的细节：
// 编码时 region 编号、region code 与节点名都会被剥掉，解析时按**序号**补回
// （第一个 region 补成 1，code 补成 "1"）。
//
// 因此访问侧看到的 region 永远是 1/"1"，而本节点自己（tailcat.Server.Region）用的是
// vpn.RegionID=901。这不影响中继的选择：一份地址只带一个 region，两端各自在自己的
// DERPMap 里解析对端与 HomeDERP，并且都连到地址里内嵌的**同一个 host:port**——真正
// 决定位置的是 HostName/DERPPort，它们原样保留（本用例正是断言这一点）。它也解释了
// PathStatus 的日志里会看到 `via DERP(1)`。见 docs/vpn-design.md 12.6 第 20 条。
func TestPeerAddressRegionNumberIsRewritten(t *testing.T) {
	region := startTestDERP(t)
	face := newTestPeerFace(t, region)

	ci, err := tailcat.ParseAddr(tailcat.Addr(face.TailcatAddr()))
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	if len(ci.Region) != 1 || len(ci.Region[0].Nodes) != 1 {
		t.Fatalf("parsed address has %d regions, want exactly 1 with 1 node", len(ci.Region))
	}
	got := ci.Region[0]
	if got.RegionID == vpn.RegionID {
		t.Fatalf("the parsed region kept RegionID %d; this case (and the design note) assume tailcat rewrites it", got.RegionID)
	}
	if got.RegionID != 1 || got.RegionCode != "1" {
		t.Fatalf("parsed region = %d/%q, want the rewritten 1/\"1\"", got.RegionID, got.RegionCode)
	}
	node := got.Nodes[0]
	if node.HostName != "127.0.0.1" || node.DERPPort != region.Nodes[0].DERPPort {
		t.Fatalf("the parsed node lost its location: %s:%d, want %s:%d",
			node.HostName, node.DERPPort, region.Nodes[0].HostName, region.Nodes[0].DERPPort)
	}
}

// TestApplyRelayOnlyWritesBothValues 固定"显式写 true 与 false"：同一个进程可能
// 先后跑多次会话（Android 的启停、托盘的切换），若只在 true 时设置，上一次留下的
// true 会让下一次的 relay_only=false 静默失效。
func TestApplyRelayOnlyWritesBothValues(t *testing.T) {
	t.Cleanup(func() { ApplyRelayOnly(false) })

	ApplyRelayOnly(true)
	if !envknob.Bool(RelayOnlyEnvKnob) {
		t.Fatalf("%s = false after ApplyRelayOnly(true)", RelayOnlyEnvKnob)
	}
	ApplyRelayOnly(false)
	if envknob.Bool(RelayOnlyEnvKnob) {
		t.Fatalf("%s is still true after ApplyRelayOnly(false); a later session could not turn relay_only off", RelayOnlyEnvKnob)
	}
}

// TestClientSetNeverFetchesWithoutPeers 是上面那条断言的阴性对照：没有对端时
// 同样不访问 DERP map（访问侧根本不建立隧道）。
func TestClientSetNeverFetchesWithoutPeers(t *testing.T) {
	cache := &recordingDERPMapCache{}
	clients, err := NewClientSet(ClientSetOptions{KeyPath: peerTestPath(t, "client.key"), DERPMapCache: cache})
	if err != nil {
		t.Fatalf("NewClientSet: %v", err)
	}
	defer func() { _ = clients.Close() }()

	if gets, puts := cache.accesses(); gets != 0 || puts != 0 {
		t.Fatalf("constructing a client set touched the DERP map cache (get=%d, put=%d)", gets, puts)
	}
}

// TestPathStatusReportsDerpForUnknownRegion 固定 Path 的字符串形态：日志里要能一眼
// 看出"走的是中继还是直连"。
func TestPathString(t *testing.T) {
	if got := (Path{Endpoint: "1.2.3.4:41641", Direct: true}).String(); got != "direct 1.2.3.4:41641" {
		t.Fatalf("direct path string = %q", got)
	}
	if got := (Path{DERPRegionCode: vpn.RegionCode}).String(); got != "via DERP("+vpn.RegionCode+")" {
		t.Fatalf("relayed path string = %q", got)
	}
}
