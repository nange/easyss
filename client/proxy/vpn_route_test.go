package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
)

// fakeVPNRoute 是 VPNRoute 的可观测替身：记录代理层交给它的目标，并按注入的拨号
// 函数返回连接。它使 client/proxy 可以在不引入 tailcat（进而整个 WireGuard 引擎）
// 的前提下验证注入面契约——真实的隧道行为由 vpn/node 的用例覆盖。
type fakeVPNRoute struct {
	// peers 是 host（小写）到规范名的映射。
	peers map[string]string
	// static 是可选静态名能力（见 VPNStaticNames）的映射：DNS 问题名 → overlay
	// IPv4。为 nil 时 ResolveStatic 一律返回 false，DNS 行为与没有该能力一致。
	static map[string]netip.Addr

	mu       sync.Mutex
	tcpDials []string
	udpDials []string

	dialTCP func(ctx context.Context, target string) (net.Conn, error)
	dialUDP func(ctx context.Context, target string) (net.Conn, error)
}

func (f *fakeVPNRoute) Lookup(host string) (string, bool) {
	name, ok := f.peers[strings.ToLower(host)]
	return name, ok
}

// ResolveStatic 是可选静态名能力。替身默认实现它，
// 因为真实的注入面（vpn/node.Route）也同时实现两者。
func (f *fakeVPNRoute) ResolveStatic(name string) (netip.Addr, bool) {
	addr, ok := f.static[name]
	return addr, ok
}

func (f *fakeVPNRoute) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	f.mu.Lock()
	f.tcpDials = append(f.tcpDials, target)
	f.mu.Unlock()
	return f.dialTCP(ctx, target)
}

func (f *fakeVPNRoute) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	f.mu.Lock()
	f.udpDials = append(f.udpDials, target)
	f.mu.Unlock()
	return f.dialUDP(ctx, target)
}

func (f *fakeVPNRoute) udpTargets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.udpDials...)
}

func (f *fakeVPNRoute) tcpTargets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tcpDials...)
}

// newVPNTestServer 构造一个注入了 VPN 的 SOCKS5 服务器。direct 为 nil 时直连拨号
// 一律失败：任何落到直连路径的目标都会让用例显式失败，而不是悄悄从物理网卡发出去。
func newVPNTestServer(t *testing.T, vpn VPNRoute, direct func(context.Context, string, string) (net.Conn, error)) *Socks5Server {
	t.Helper()
	if direct == nil {
		direct = func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("the direct dialer must not be used for a vpn peer")
		}
	}
	srv, err := NewSocks5Server(Socks5Options{
		// NewDirectOnly 把所有目标判直连：它让本文件能证明"VPN 命中发生在 router
		// 之前"——若顺序反了，目标会走直连分支并触发上面那个报错的拨号器。
		Router:            router.NewDirectOnly(),
		Handler:           newTestStreamHandler(&mockTransport{}),
		Method:            protocol.MethodAES256GCM,
		DirectDialContext: direct,
		VPN:               vpn,
		Timeouts: config.Timeouts{
			Dial:       5 * time.Second,
			StreamIdle: 5 * time.Second,
			UDPIdle:    5 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// TestDecidePrefersVPNPeerOverRouter 固定判定顺序：对端必须在调用 router 之前被
// 认出来。反例是"未知域名 → 走代理"——目标最终会被送进 easyss 服务器，而它同样
// 不认识这个名字。
func TestDecidePrefersVPNPeerOverRouter(t *testing.T) {
	fake := &fakeVPNRoute{peers: map[string]string{"b": "b"}}
	policy := newRoutePolicy(routePolicyOptions{Router: router.NewDirectOnly(), VPN: fake})

	if got := policy.decide("b").Action; got != routeVPN {
		t.Fatalf("decide(b) = %s, want vpn", got)
	}
	// 大小写不敏感：DNS 名字本身不区分大小写，应用可能写 B。
	if got := policy.decide("B").Action; got != routeVPN {
		t.Fatalf("decide(B) = %s, want vpn", got)
	}
	// 非对端仍由 router 决定（NewDirectOnly 全部判直连），说明 VPN 检查没有吞掉
	// 其他目标。
	if got := policy.decide("example.com").Action; got != routeDirect {
		t.Fatalf("decide(example.com) = %s, want direct (the router must still be consulted)", got)
	}
	// VPN 关闭（nil）时行为必须与既有版本完全一致。
	plain := newRoutePolicy(routePolicyOptions{Router: router.NewDirectOnly()})
	if got := plain.decide("b").Action; got != routeDirect {
		t.Fatalf("decide(b) without a vpn route = %s, want direct", got)
	}
}

// TestVPNRouteCarriesTCPToTheProxyLayer 验证 TCP 注入：对端名经 SOCKS5 CONNECT
// 进来后走 VPN 拨号，且代理层把**访问侧的原始目标**交给注入面（归一化成字面
// 127.0.0.1 是实现内部的事，见 vpn/node/route.go）。
func TestVPNRouteCarriesTCPToTheProxyLayer(t *testing.T) {
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()
	fake := &fakeVPNRoute{
		peers: map[string]string{"b": "b"},
		dialTCP: func(context.Context, string) (net.Conn, error) {
			return net.Dial("tcp", echoAddr)
		},
	}
	srv := newVPNTestServer(t, fake, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()

	conn := socks5HandshakeConnectRaw(t, ln.Addr().String(), "b:8080")
	payload := []byte("through the vpn")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := conn.Read(got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}

	if targets := fake.tcpTargets(); !slices.Equal(targets, []string{"b:8080"}) {
		t.Fatalf("vpn TCP dials = %v, want exactly [b:8080]", targets)
	}
}

// TestVPNRouteCarriesUDPToTheProxyLayer 验证 UDP 注入：一条发往对端的数据报经 VPN
// 拨号打开会话，回包按**客户端的原始目标**组帧（tun2socks 以该地址为 UDP 流建键，
// 换个源地址的数据报会被丢弃），且会话键带 vpn_ 前缀并用对端规范名。
func TestVPNRouteCarriesUDPToTheProxyLayer(t *testing.T) {
	echoAddr, stopEcho := startUDPEcho(t)
	defer stopEcho()

	clientSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	t.Cleanup(func() { clientSock.Close() }) //nolint:errcheck

	fake := &fakeVPNRoute{
		peers: map[string]string{"b": "b"},
		dialUDP: func(context.Context, string) (net.Conn, error) {
			return net.Dial("udp", echoAddr)
		},
	}
	srv := newVPNTestServer(t, fake, nil)
	relay := newDisposableUDPRelay(t, srv, clientSock.LocalAddr().(*net.UDPAddr))

	payload := []byte("datagram through the vpn")
	const target = "b:5353"
	if err := srv.handleUDP(relay, &socks5Frame{cmd: 3, target: target}, payload); err != nil {
		t.Fatalf("handleUDP: %v", err)
	}

	// 拨号在 handleUDP 返回前同步完成（会话池的创建路径）。
	if got := fake.udpTargets(); !slices.Equal(got, []string{target}) {
		t.Fatalf("vpn UDP dials = %v, want exactly [%s]", got, target)
	}
	// 会话键带对端规范名**与目标端口**：同一对端的另一个端口必须是另一条流，
	// 否则第二个端口的数据报会被投递到第一个端口上（见 vpnUDPRelay）。
	key := "vpn_" + clientSock.LocalAddr().String() + "_b_5353"
	if _, ok := srv.udp.directFor(key); !ok {
		t.Fatalf("the vpn session was not registered under %q", key)
	}
	if _, ok := srv.udp.directFor("vpn_" + clientSock.LocalAddr().String() + "_b_5354"); ok {
		t.Fatalf("a different port on the same peer must not share the session")
	}

	if err := clientSock.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := clientSock.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read the relayed datagram: %v", err)
	}
	src, data := parseUDPFrame(t, buf[:n])
	if src != target {
		t.Errorf("reply source = %s, want the client's original target %s", src, target)
	}
	if string(data) != string(payload) {
		t.Errorf("reply payload = %q, want %q", data, payload)
	}
}

// TestVPNPeerBypassesUDPPublicPathGates 固定"对端优先于公网路径门禁"这条顺序：
// disable_quic 会静默吞掉 443 的数据报，53 拦截会按查询域名把发往对端 53 的查询
// 重新分流——两者对"访问对端本机的服务端口"都是错的（用户的目标是端口互通）。
func TestVPNPeerBypassesUDPPublicPathGates(t *testing.T) {
	silent := startSilentRemoteUDP(t)
	newFake := func() *fakeVPNRoute {
		return &fakeVPNRoute{
			peers: map[string]string{"b": "b"},
			dialUDP: func(context.Context, string) (net.Conn, error) {
				return net.Dial("udp", silent)
			},
		}
	}

	t.Run("QUIC 屏蔽不吞对端的 443", func(t *testing.T) {
		fake := newFake()
		srv := newVPNTestServer(t, fake, nil)
		srv.disableQUIC = true
		sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sock.Close() }) //nolint:errcheck

		relay := srv.registerTestUDPRelay(sock, sock.LocalAddr().(*net.UDPAddr))
		if err := srv.handleUDP(relay, &socks5Frame{cmd: 3, target: "b:443"}, []byte{1}); err != nil {
			t.Fatalf("handleUDP: %v", err)
		}
		if got := fake.udpTargets(); !slices.Equal(got, []string{"b:443"}) {
			t.Fatalf("vpn UDP dials = %v, want [b:443] (disable_quic must not swallow a peer's port)", got)
		}
	})

	t.Run("53 拦截不吞对端的 53", func(t *testing.T) {
		fake := newFake()
		srv := newVPNTestServer(t, fake, nil)
		sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sock.Close() }) //nolint:errcheck

		// 载荷是一条真的 DNS 查询：否则本用例证明不了"53 拦截被让路"——非 DNS
		// 载荷本来就会回落到普通 UDP 分流。
		query := new(dns.Msg)
		query.SetQuestion("example.com.", dns.TypeA)
		payload, err := query.Pack()
		if err != nil {
			t.Fatal(err)
		}

		relay := srv.registerTestUDPRelay(sock, sock.LocalAddr().(*net.UDPAddr))
		if err := srv.handleUDP(relay, &socks5Frame{cmd: 3, target: "b:53"}, payload); err != nil {
			t.Fatalf("handleUDP: %v", err)
		}
		if got := fake.udpTargets(); !slices.Equal(got, []string{"b:53"}) {
			t.Fatalf("vpn UDP dials = %v, want [b:53] (the dns interceptor must not hijack a peer's port 53)", got)
		}
	})
}

// TestVPNPeerBypassesTCPDNSInterception 是 TCP 侧的对应保证：发往对端 53 的连接
// 必须被当作普通服务端口，而不是 DNS over TCP。
func TestVPNPeerBypassesTCPDNSInterception(t *testing.T) {
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()
	fake := &fakeVPNRoute{
		peers: map[string]string{"b": "b"},
		dialTCP: func(context.Context, string) (net.Conn, error) {
			return net.Dial("tcp", echoAddr)
		},
	}
	srv := newVPNTestServer(t, fake, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()

	conn := socks5HandshakeConnectRaw(t, ln.Addr().String(), "b:53")
	payload := []byte("not a dns message")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := conn.Read(got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
	if targets := fake.tcpTargets(); !slices.Equal(targets, []string{"b:53"}) {
		t.Fatalf("vpn TCP dials = %v, want [b:53]", targets)
	}
}
