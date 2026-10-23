package vpnnode

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tailcat "github.com/tailscale/tailcat"
	"tailscale.com/envknob"
	"tailscale.com/net/netx"
	"tailscale.com/types/key"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/stats"

	vpn "github.com/nange/easyss/v3/vpn"
)

// recordingDERPMapCache 记录对 tailcat DERP map 缓存的任何访问。
// 这是"零官方 DERPMap 请求"的判据：地址若是短格式，Expand 会先查缓存再回退到官方
// URL（常量、无法替换），因此缓存访问就是等价证据。
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
	return newAccessSideWith(t, face, clientKey, cache, ClientSetOptions{})
}

// newAccessSideWith 与 newAccessSide 相同，但允许调用方追加客户端集合选项
// （DERPDialer / DERPOnly 都必须在客户端第一次拨号之前落位）。
func newAccessSideWith(t *testing.T, face *PeerFace, clientKey key.NodePrivate,
	cache tailcat.DERPMapCache, extra ClientSetOptions) (*Route, *ClientSet) {
	t.Helper()

	ref := PeerRef{HostName: "b", Address: face.TailcatAddr(), Port: face.opts.PeerPort}
	extra.Key = clientKey
	extra.Peers = []PeerRef{ref}
	extra.DERPMapCache = cache
	clients, err := NewClientSet(extra)
	if err != nil {
		t.Fatalf("NewClientSet: %v", err)
	}
	t.Cleanup(func() { _ = clients.Close() })

	overlay, err := Assign(config.DefaultVPNOverlayPrefix(), []PeerRef{ref})
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	route, err := NewRoute(RouteOptions{
		Overlay:  overlay,
		Clients:  clients,
		Timeouts: config.Timeouts{Dial: 40 * time.Second, Base: 30 * time.Second},
	})
	if err != nil {
		t.Fatalf("NewRoute: %v", err)
	}
	return route, clients
}

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

// TestVPNNodeEndToEndNeverFetchesTheOfficialDERPMap 按生产路径组装对端面与访问侧，
// 钉住"零官方 DERPMap 请求"与 allow_clients 白名单（只接受 client.key 里那把 key）。
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

// TestVPNNodeRelayOnlyUsesTheRelay 钉住 relay_only 的后果：隧道仍可用，但没有直连路径
// （magicsock 绑 newBlockForeverConn，不创建 UDP socket）。
// 用 PathStatus 观测：UDP 出口存在时 Endpoint 会被填上，开了开关则必然为空。
func TestVPNNodeRelayOnlyUsesTheRelay(t *testing.T) {
	// 只在 tailcat 创建引擎时生效，因此必须在 Start/首次拨号之前落位。
	t.Cleanup(func() { envknob.Setenv(derpOnlyEnvKnob, "false") })

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
	identity, err := LoadOrCreateNodeIdentity(peerTestPath(t, "node-identity.json"))
	if err != nil {
		t.Fatalf("LoadOrCreateNodeIdentity: %v", err)
	}
	face := newTestPeerFaceWithOptions(t, PeerFaceOptions{
		Identity:     identity,
		Region:       region,
		PeerPort:     peerTestPort(t),
		AllowClients: []key.NodePublic{clientKey.Public()},
		DERPOnly:     true,
	})
	if err := face.Start(context.Background()); err != nil {
		t.Fatalf("PeerFace.Start: %v", err)
	}
	defer func() { _ = face.Stop() }()
	if !envknob.Bool(derpOnlyEnvKnob) {
		t.Fatalf("%s was not set by tailcat's DERPOnly", derpOnlyEnvKnob)
	}

	route, clients := newAccessSideWith(t, face, clientKey, nil, ClientSetOptions{DERPOnly: true})

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

// TestPeerAddressRegionNumberIsRewritten 钉住 tailcat 地址往返的易误读细节：编码时
// region 编号/code/节点名被剥掉，解析时按**序号**补回（1/"1"），HostName/DERPPort 原样保留。
// 访问侧看到的 region 因此恒为 1，本节点自己用 vpn.RegionID；中继选择不受影响。
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

// derpOnlyEnvKnob 是 tailcat 的 DERPOnly 写进去的那个 tailscale 开关，用于断言
// "relay_only 真的落到了数据面"；true/false 的写入由 tailcat 自己的测试固定。
const derpOnlyEnvKnob = "TS_DEBUG_ALWAYS_USE_DERP"

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

// 钉住 Path 的字符串形态：日志里要能一眼看出走的是中继还是直连。
func TestPathString(t *testing.T) {
	if got := (Path{Endpoint: "1.2.3.4:41641", Direct: true}).String(); got != "direct 1.2.3.4:41641" {
		t.Fatalf("direct path string = %q", got)
	}
	if got := (Path{DERPRegionCode: vpn.RegionCode}).String(); got != "via DERP("+vpn.RegionCode+")" {
		t.Fatalf("relayed path string = %q", got)
	}
}

// TestVPNNodeUsesTheInjectedDERPDialer 钉住跨包契约：真实隧道里双方的 DERP 连接都
// 必须经过调用方注入的 DERPDialer。
// 私有 DERP 只接待回环来源，tailcat 的默认拨号器直连必然失败（见 runner/derpdialer.go）。
func TestVPNNodeUsesTheInjectedDERPDialer(t *testing.T) {
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
	identity, err := LoadOrCreateNodeIdentity(peerTestPath(t, "node-identity.json"))
	if err != nil {
		t.Fatalf("LoadOrCreateNodeIdentity: %v", err)
	}

	// 双方各自记录并转发：转发让隧道真的能用，记录证明走的是这个拨号器。
	faceDialer, faceDials := recordingDERPDialer(t)
	clientDialer, clientDials := recordingDERPDialer(t)

	face := newTestPeerFaceWithOptions(t, PeerFaceOptions{
		Identity:     identity,
		Region:       region,
		PeerPort:     peerTestPort(t),
		AllowClients: []key.NodePublic{clientKey.Public()},
		DERPDialer:   faceDialer,
	})
	if err := face.Start(context.Background()); err != nil {
		t.Fatalf("PeerFace.Start: %v", err)
	}
	defer func() { _ = face.Stop() }()

	route, _ := newAccessSideWith(t, face, clientKey, nil, ClientSetOptions{DERPDialer: clientDialer})
	dialEchoTCP(t, route, echoPort)

	if faceDials.Load() == 0 {
		t.Error("the peer face reached DERP without the injected dialer")
	}
	if clientDials.Load() == 0 {
		t.Error("the access side reached DERP without the injected dialer")
	}
}

// recordingDERPDialer 返回一个"记录 + 转发"的 DERP 拨号器：目标地址原样拨过去，
// 同时统计调用次数。
func recordingDERPDialer(t *testing.T) (netx.DialFunc, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	d := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		return d.DialContext(ctx, network, addr)
	}, &calls
}
