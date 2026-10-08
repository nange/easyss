package vpn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"

	"github.com/nange/easyss/v3/log"
)

// meshTestRelay 是测试用的进程内中继：真实的 derpserver 挂在真实 TLS 监听上，
// 与生产装配（vpn.NewDERPServer + derpserver.Handler）一致，因此测到的是真实协议。
type meshTestRelay struct {
	t     *testing.T
	srv   *DERPServer
	http  *httptest.Server
	addr  string         // 对端要拨（并写进 mesh_peers）的 host:port
	roots *x509.CertPool // 测试自签证书的根，供 mesh 客户端与普通客户端校验
}

func newMeshTestRelay(t *testing.T) *meshTestRelay {
	t.Helper()
	srv := NewDERPServer(key.NewNode())
	hs := httptest.NewUnstartedServer(srv.Handler())
	hs.StartTLS()
	t.Cleanup(func() {
		hs.Close()
		_ = srv.Close()
	})

	u, err := url.Parse(hs.URL)
	if err != nil {
		t.Fatalf("parse test relay URL %q: %v", hs.URL, err)
	}
	if _, err := strconv.Atoi(u.Port()); err != nil {
		t.Fatalf("test relay port %q: %v", u.Port(), err)
	}
	tr, ok := hs.Client().Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatalf("httptest client transport has no test root CAs")
	}
	return &meshTestRelay{
		t:     t,
		srv:   srv,
		http:  hs,
		addr:  u.Host,
		roots: tr.TLSClientConfig.RootCAs,
	}
}

// tlsConfig 返回能校验测试自签证书的客户端配置。
func (r *meshTestRelay) tlsConfig() *tls.Config { return &tls.Config{RootCAs: r.roots} }

// dial 建立到该中继的真实 TCP 连接（mesh 客户端注入的拨号器用它）。
func (r *meshTestRelay) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// recordingDialer 包一层拨号器并记录被拨的地址，用来断言 mesh 连接确实走了调用方
// 提供的出网路径（生产上是 SOCKS5 → easyss 隧道）。
type recordingDialer struct {
	inner func(ctx context.Context, network, addr string) (net.Conn, error)

	mu     sync.Mutex
	dialed []string
}

func (d *recordingDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, addr)
	d.mu.Unlock()
	return d.inner(ctx, network, addr)
}

func (d *recordingDialer) addrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

// peerTo 构造指向 target 的 mesh 对端：拨号走测试内的直连，TLS 信任 target 自己
// 的测试证书（每个 httptest 服务器有自己的自签证书与根池，因此必须按对端取）。
func peerTo(target *meshTestRelay, dial func(ctx context.Context, network, addr string) (net.Conn, error)) MeshPeer {
	return MeshPeer{Addr: target.addr, Dial: dial, TLSConfig: target.tlsConfig()}
}

// startMesh 启动一个中继的 mesh 客户端。
func startMesh(t *testing.T, relay *meshTestRelay, meshKey string, peers ...MeshPeer) *Mesh {
	t.Helper()
	m, err := NewMesh(relay.srv, MeshOptions{MeshKey: meshKey, Peers: peers})
	if err != nil {
		t.Fatalf("NewMesh: %v", err)
	}
	if err := m.Start(t.Context()); err != nil {
		t.Fatalf("Mesh.Start: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// meshTestClient 是一个挂在某个中继上的普通 DERP 客户端（不带 mesh key）。
type meshTestClient struct {
	t    *testing.T
	key  key.NodePrivate
	dc   *derphttp.Client
	recv chan []byte
}

func newMeshTestClient(t *testing.T, relay *meshTestRelay) *meshTestClient {
	t.Helper()
	c := &meshTestClient{t: t, key: key.NewNode(), recv: make(chan []byte, 16)}
	dc, err := derphttp.NewClient(c.key, "https://"+relay.addr+"/derp", t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("derphttp.NewClient(%s): %v", relay.addr, err)
	}
	c.dc = dc
	c.dc.TLSConfig = relay.tlsConfig()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := c.dc.Connect(ctx); err != nil {
		t.Fatalf("connect a DERP client to %s: %v", relay.addr, err)
	}
	t.Cleanup(func() { _ = c.dc.Close() })

	go func() {
		for {
			m, err := c.dc.Recv()
			if err != nil {
				close(c.recv)
				return
			}
			if dm, ok := m.(derp.ReceivedPacket); ok {
				select {
				case c.recv <- append([]byte(nil), dm.Data...):
				default:
				}
			}
		}
	}()
	return c
}

// sendUntilDelivered 反复发送直到对端收到（或超时）。mesh 是异步建立的：订阅循环
// 要先连上、拿到 PeerPresent，本机才会登记转发映射，因此测试必须容忍这个窗口，
// 而不是在第一次 Send 之后就断言。
func sendUntilDelivered(t *testing.T, from *meshTestClient, to *meshTestClient, payload []byte) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := from.dc.Send(to.key.Public(), payload); err != nil {
			lastErr = err
		}
		select {
		case got, ok := <-to.recv:
			if !ok {
				t.Fatalf("the receiving client's connection dropped (last send error: %v)", lastErr)
			}
			if string(got) != string(payload) {
				t.Fatalf("received %q, want %q", got, payload)
			}
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatalf("the packet was not delivered through the mesh within the deadline (last send error: %v)", lastErr)
}

// TestMeshForwardsPacketsBetweenTwoRelays 是需求 3 的核心断言：两个中继各自挂一个
// 客户端，客户端 A 发往客户端 B 的数据包在本机中继上找不到 B，于是沿 mesh 连接转发
// 给另一台中继，由它投递给本地的 B。
func TestMeshForwardsPacketsBetweenTwoRelays(t *testing.T) {
	relayA := newMeshTestRelay(t)
	relayB := newMeshTestRelay(t)

	dialToB := &recordingDialer{inner: relayB.dial}
	startMesh(t, relayA, "shared-mesh-passphrase", peerTo(relayB, dialToB.dial))
	startMesh(t, relayB, "shared-mesh-passphrase", peerTo(relayA, relayA.dial))

	clientA := newMeshTestClient(t, relayA)
	clientB := newMeshTestClient(t, relayB)

	sendUntilDelivered(t, clientA, clientB, []byte("hello from A"))

	// 拨号器必须被以对端声明的 host:port 调用：这正是"mesh 连接经调用方出网路径"
	// 的可观测证据（生产上它是 SOCKS5 → easyss 隧道，而不是直连对端公网端口）。
	if addrs := dialToB.addrs(); !slices.Contains(addrs, relayB.addr) {
		t.Errorf("the injected dialer was called with %v, want it to include %q", addrs, relayB.addr)
	}
}

// TestMeshWithoutMatchingKeyDoesNotForward 固定 key 的重要性：mesh key 不一致时
// 对端只被当成普通 DERP 客户端，订阅连接变化被拒（上游返回 insufficient
// permissions），于是没有任何转发映射，包只会被丢弃。
//
// 它同时确认失败是**可见**的（一条 WARN 指出哪个对端不可用），而不是静默地
// "VPN 时好时坏"。
func TestMeshWithoutMatchingKeyDoesNotForward(t *testing.T) {
	var logs logBuffer
	restore := captureLogs(t, &logs)
	defer restore()

	relayA := newMeshTestRelay(t)
	relayB := newMeshTestRelay(t)

	startMesh(t, relayA, "key-of-a", peerTo(relayB, relayB.dial))
	// B 侧用另一个密钥加入 mesh：对端因此不被当成可信中继。
	startMesh(t, relayB, "key-of-b", peerTo(relayA, relayA.dial))

	clientA := newMeshTestClient(t, relayA)
	clientB := newMeshTestClient(t, relayB)

	// 反复发一小段时间：这里期望的是"始终收不到"。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = clientA.dc.Send(clientB.key.Public(), []byte("should not arrive"))
		select {
		case got := <-clientB.recv:
			t.Fatalf("a packet arrived although the mesh keys differ: %q", got)
		case <-time.After(100 * time.Millisecond):
		}
	}

	// 首次失败必须留下一条指出对端的警告（之后降级为 Debug，避免每 5 秒刷屏）。
	if !logs.contains("level=WARN") || !logs.contains(relayB.addr) {
		t.Errorf("no WARN naming the unusable peer %s was logged:\n%s", relayB.addr, logs.String())
	}
	if !logs.contains("mesh_key") {
		t.Errorf("the warning should point at server.vpn.mesh_key:\n%s", logs.String())
	}
}

// TestMeshCloseStopsForwarding 固定拆除语义：Close 之后不再有新登记/保留的转发
// 映射，且重复 Close 是幂等的（退出路径与切换路径可能各调一次）。
func TestMeshCloseStopsForwarding(t *testing.T) {
	relayA := newMeshTestRelay(t)
	relayB := newMeshTestRelay(t)

	meshA := startMesh(t, relayA, "shared-mesh-passphrase", peerTo(relayB, relayB.dial))
	startMesh(t, relayB, "shared-mesh-passphrase", peerTo(relayA, relayA.dial))

	clientA := newMeshTestClient(t, relayA)
	clientB := newMeshTestClient(t, relayB)
	sendUntilDelivered(t, clientA, clientB, []byte("before close"))

	if err := meshA.Close(); err != nil {
		t.Fatalf("Mesh.Close: %v", err)
	}
	if err := meshA.Close(); err != nil {
		t.Fatalf("Mesh.Close (second call): %v", err)
	}

	// 转发映射已经随订阅循环的退出被移除：A 侧再发包只会被丢弃（B 侧仍连着，因此
	// 这不是"连接断了"造成的假阴性）。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = clientA.dc.Send(clientB.key.Public(), []byte("after close"))
		select {
		case got := <-clientB.recv:
			t.Fatalf("a packet was still forwarded after Close: %q", got)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// TestNewMeshValidation 固定构造期校验：没有中继、没有密钥、没有拨号器、地址非法
// 或重复都必须在启动前失败——这些错误如果漏到运行期，表现都是"包被静默丢弃"。
func TestNewMeshValidation(t *testing.T) {
	relay := newMeshTestRelay(t)
	ok := MeshPeer{Addr: "relay-b.example.com:443", Dial: relay.dial}

	t.Run("没有内嵌 DERP 中继", func(t *testing.T) {
		if _, err := NewMesh(nil, MeshOptions{MeshKey: "k", Peers: []MeshPeer{ok}}); err == nil {
			t.Error("NewMesh(nil, ...) = nil error, want an error")
		}
		if _, err := NewMesh(&DERPServer{}, MeshOptions{MeshKey: "k", Peers: []MeshPeer{ok}}); err == nil {
			t.Error("NewMesh with an empty DERPServer = nil error, want an error")
		}
	})

	t.Run("没有对端", func(t *testing.T) {
		if _, err := NewMesh(relay.srv, MeshOptions{MeshKey: "k"}); err == nil {
			t.Error("NewMesh without peers = nil error, want an error")
		}
	})

	t.Run("空 mesh key", func(t *testing.T) {
		if _, err := NewMesh(relay.srv, MeshOptions{MeshKey: "  ", Peers: []MeshPeer{ok}}); err == nil {
			t.Error("NewMesh with an empty mesh key = nil error, want an error")
		}
	})

	t.Run("对端地址非法", func(t *testing.T) {
		if _, err := NewMesh(relay.srv, MeshOptions{MeshKey: "k", Peers: []MeshPeer{{Addr: "not-a-host-port", Dial: relay.dial}}}); err == nil {
			t.Error("NewMesh with an invalid peer address = nil error, want an error")
		}
	})

	t.Run("对端重复", func(t *testing.T) {
		dup := MeshPeer{Addr: "Relay-B.Example.com:443", Dial: relay.dial}
		if _, err := NewMesh(relay.srv, MeshOptions{MeshKey: "k", Peers: []MeshPeer{ok, dup}}); err == nil {
			t.Error("NewMesh with a duplicated peer = nil error, want an error")
		}
	})

	t.Run("没有拨号器", func(t *testing.T) {
		if _, err := NewMesh(relay.srv, MeshOptions{MeshKey: "k", Peers: []MeshPeer{{Addr: "relay-b.example.com:443"}}}); err == nil {
			t.Error("NewMesh without a dialer = nil error, want an error")
		}
	})
}

// TestMeshStartIsSingleShot 固定生命周期契约：重复 Start 报错，Close 之后不能再
// Start，而 Close 本身幂等且 nil 安全。
func TestMeshStartIsSingleShot(t *testing.T) {
	relay := newMeshTestRelay(t)
	m, err := NewMesh(relay.srv, MeshOptions{MeshKey: "k", Peers: []MeshPeer{{Addr: "relay-b.example.com:443", Dial: relay.dial}}})
	if err != nil {
		t.Fatalf("NewMesh: %v", err)
	}
	if err := m.Start(t.Context()); err != nil {
		t.Fatalf("Mesh.Start: %v", err)
	}
	if err := m.Start(t.Context()); err == nil {
		t.Error("the second Start = nil error, want an error")
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Mesh.Close: %v", err)
	}
	if err := m.Start(t.Context()); err == nil {
		t.Error("Start after Close = nil error, want an error")
	}
	if err := (*Mesh)(nil).Close(); err != nil {
		t.Errorf("Close on a nil Mesh = %v, want nil", err)
	}
}

// TestMeshCloseOnUnstartedMesh 固定"从未启动的 Mesh 不需要清理"：Start 之前
// Close 必须直接返回，而不会去碰还不存在的客户端。
func TestMeshCloseOnUnstartedMesh(t *testing.T) {
	relay := newMeshTestRelay(t)
	m, err := NewMesh(relay.srv, MeshOptions{MeshKey: "k", Peers: []MeshPeer{{Addr: "relay-b.example.com:443", Dial: relay.dial}}})
	if err != nil {
		t.Fatalf("NewMesh: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Errorf("Close before Start = %v, want nil", err)
	}
}

// TestMeshSelfConnectIsWarned 固定"代理落到了本机自己的中继"这一误配的可见性：
// 此时 TLS 未必失败（同一个域名/证书），但 mesh 边根本不存在（上游检测到自连后
// 直接放弃该 host），因此必须有一条点名对端的警告。
func TestMeshSelfConnectIsWarned(t *testing.T) {
	var logs logBuffer
	restore := captureLogs(t, &logs)
	defer restore()

	relay := newMeshTestRelay(t)
	// 对端地址故意指向本机自己：TLS 与协议都会成功，只有"连到的是自己"这一条线索。
	startMesh(t, relay, "shared-mesh-passphrase", peerTo(relay, relay.dial))

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), "own relay") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no warning about the self-connect was logged:\n%s", logs.String())
}

// ---- 测试辅助 ----

// logBuffer 是并发安全的日志缓冲：mesh 的日志来自多个 goroutine。
type logBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *logBuffer) contains(s string) bool { return strings.Contains(l.String(), s) }

// captureLogs 把 easyss 的日志器换成写入 buf 的 slog，返回恢复函数。
//
// mesh 的日志来自多个 goroutine（每个对端一个订阅循环 + 首连观测），因此断言不能
// 只依赖返回值，必须盯住"用户最终能看到什么"。
func captureLogs(t *testing.T, buf *logBuffer) func() {
	t.Helper()
	prev := log.Logger()
	log.SetLogger(slog.New(slog.NewTextHandler(buf, nil)))
	return func() { log.SetLogger(prev) }
}

// 编译期断言：derpserver 的 PacketForwarder 由 *derphttp.Client 实现（mesh 把
// 客户端本身登记为转发器）。
var _ derpserver.PacketForwarder = (*derphttp.Client)(nil)
