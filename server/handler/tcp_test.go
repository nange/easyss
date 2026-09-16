package handler

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
)

// testPublicV4/testPublicV6 是拨号测试使用的公网地址：拨号后的 SSRF 防护会
// 拒绝 LAN 与文档网段（192.0.2.0/24、2001:db8::/32），因此这里必须用真实
// 公网地址，测试才能走到拨号层。
const (
	testPublicV4 = "93.184.216.34"
	testPublicV6 = "2606:2800:220:1:248:1893:25c8:1946"
)

// TestNetworksFor 固定基础网络名到具体地址族的映射：只有具体族才不会再次
// 触发操作系统的双栈选择，因此这是"按候选地址逐个拨号"的前提。
func TestNetworksFor(t *testing.T) {
	v4 := netip.MustParseAddr(testPublicV4)
	v6 := netip.MustParseAddr(testPublicV6)

	tests := []struct {
		name    string
		network string
		ip      netip.Addr
		want    string
	}{
		{name: "tcp ipv4", network: "tcp", ip: v4, want: "tcp4"},
		{name: "tcp ipv6", network: "tcp", ip: v6, want: "tcp6"},
		{name: "udp ipv4", network: "udp", ip: v4, want: "udp4"},
		{name: "udp ipv6", network: "udp", ip: v6, want: "udp6"},
		{name: "icmp ipv4", network: "ip", ip: v4, want: "ip4"},
		{name: "icmp ipv6", network: "ip", ip: v6, want: "ip6"},
		{name: "already concrete", network: "tcp4", ip: v6, want: "tcp4"},
		{name: "icmp raw network", network: "ip4:icmp", ip: v4, want: "ip4:icmp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeNetwork(tt.network, tt.ip); got != tt.want {
				t.Fatalf("normalizeNetwork(%q, %v) = %q, want %q", tt.network, tt.ip, got, tt.want)
			}
		})
	}
}

// stubLookupIPAddr 替换包内的解析函数，使拨号候选排序不依赖真实 DNS。
func stubLookupIPAddr(t *testing.T, addrs ...string) {
	t.Helper()
	prev := lookupIPAddr
	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		out := make([]net.IPAddr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, net.IPAddr{IP: net.ParseIP(a)})
		}
		return out, nil
	}
	t.Cleanup(func() { lookupIPAddr = prev })
}

// TestOrderDialCandidates 覆盖出站地址族的选型：字面 IP 目标只有一个候选
// （族由目标自身决定，与客户端偏好无关），域名目标把客户端所属族排在候选
// 列表前面、另一族保留作为回退。
func TestOrderDialCandidates(t *testing.T) {
	v4 := netip.MustParseAddr(testPublicV4)
	v6 := netip.MustParseAddr(testPublicV6)
	wantAddrs := func(t *testing.T, got []netip.Addr, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("candidates = %v, want %v", got, want)
		}
		for i, w := range want {
			if got[i].String() != w {
				t.Fatalf("candidates = %v, want %v", got, want)
			}
		}
	}

	t.Run("literal ipv4 target", func(t *testing.T) {
		cands, err := orderDialCandidates(t.Context(), testPublicV4+":443", v6)
		if err != nil {
			t.Fatalf("orderDialCandidates: %v", err)
		}
		wantAddrs(t, cands, testPublicV4)
	})

	t.Run("literal ipv6 target", func(t *testing.T) {
		cands, err := orderDialCandidates(t.Context(), "["+testPublicV6+"]:443", v4)
		if err != nil {
			t.Fatalf("orderDialCandidates: %v", err)
		}
		wantAddrs(t, cands, testPublicV6)
	})

	t.Run("literal ipv4-mapped folds to ipv4", func(t *testing.T) {
		cands, err := orderDialCandidates(t.Context(), "[::ffff:"+testPublicV4+"]:80", v4)
		if err != nil {
			t.Fatalf("orderDialCandidates: %v", err)
		}
		wantAddrs(t, cands, testPublicV4)
	})

	t.Run("dual stack domain prefers the client family", func(t *testing.T) {
		stubLookupIPAddr(t, testPublicV6, testPublicV4)
		cands, err := orderDialCandidates(t.Context(), "example.com:443", v4)
		if err != nil {
			t.Fatalf("orderDialCandidates: %v", err)
		}
		wantAddrs(t, cands, testPublicV4, testPublicV6)
	})

	t.Run("v6 client over a dual stack domain keeps v6 first", func(t *testing.T) {
		stubLookupIPAddr(t, testPublicV6, testPublicV4)
		cands, err := orderDialCandidates(t.Context(), "example.com:443", v6)
		if err != nil {
			t.Fatalf("orderDialCandidates: %v", err)
		}
		wantAddrs(t, cands, testPublicV6, testPublicV4)
	})

	t.Run("v4 client falls back to the only available family", func(t *testing.T) {
		stubLookupIPAddr(t, testPublicV6)
		cands, err := orderDialCandidates(t.Context(), "example.com:443", v4)
		if err != nil {
			t.Fatalf("orderDialCandidates: %v", err)
		}
		wantAddrs(t, cands, testPublicV6)
	})

	t.Run("bare ipv6 without port is not treated as a domain", func(t *testing.T) {
		cands, err := orderDialCandidates(t.Context(), testPublicV6, v4)
		if err != nil {
			t.Fatalf("orderDialCandidates: %v", err)
		}
		wantAddrs(t, cands, testPublicV6)
	})

	t.Run("resolution failure is reported", func(t *testing.T) {
		prev := lookupIPAddr
		lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
			return nil, errors.New("dns boom")
		}
		t.Cleanup(func() { lookupIPAddr = prev })

		if _, err := orderDialCandidates(t.Context(), "example.com:443", v4); err == nil {
			t.Fatal("orderDialCandidates should report the resolution failure")
		}
	})
}

// probeNetDialer 是 dialOutbound 的测试拨号器：记录每次尝试实际拨给的地址
// （形如 "tcp4 93.184.216.34:443"），并可对指定目标制造失败，从而在不产生
// 真实流量的前提下断言候选顺序与回退行为。
type probeNetDialer struct {
	attempts []string
	fail     func(target string) bool
	// err 是失败时返回的错误，nil 时使用通用的"network unreachable"。
	err     error
	timeout time.Duration
}

func (d *probeNetDialer) DialContext(_ context.Context, network, target string) (net.Conn, error) {
	d.attempts = append(d.attempts, network+" "+target)
	if d.fail != nil && d.fail(target) {
		if d.err != nil {
			return nil, d.err
		}
		return nil, errors.New("network unreachable")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return newStubConn(&net.IPAddr{IP: net.ParseIP(target)}), nil
	}
	// 连接报告的远端地址等于拨号时使用的目标，调用方据此校验实际拨给的地址。
	n, _ := strconv.Atoi(port)
	return newStubConn(&net.TCPAddr{IP: net.ParseIP(host), Port: n}), nil
}

func (d *probeNetDialer) Timeout() time.Duration {
	if d.timeout > 0 {
		return d.timeout
	}
	return 30 * time.Second
}

// TestDialOutboundFamilySelection 覆盖 dialOutbound 实际拨给的网络名与目标：
// 字面 IP 目标按目标自身定族，域名目标按客户端族排序后逐个尝试；没有偏好时
// 目标原样交给系统解析器。这里直接调用 dialOutbound 而不是走 handler 的拨号
// 闭包——后者的 h.dialContext 是测试注入点，会在到达 dialOutbound 之前短路。
func TestDialOutboundFamilySelection(t *testing.T) {
	v4 := netip.MustParseAddr(testPublicV4)
	v6 := netip.MustParseAddr(testPublicV6)
	neverFail := func(string) bool { return false }

	t.Run("ipv4 literal", func(t *testing.T) {
		d := &probeNetDialer{fail: neverFail}
		if _, err := dialOutbound(t.Context(), d, "tcp", testPublicV4+":443", v6); err != nil {
			t.Fatalf("dialOutbound: %v", err)
		}
		want := []string{"tcp4 " + testPublicV4 + ":443"}
		if !slices.Equal(d.attempts, want) {
			t.Errorf("attempts = %v, want %v", d.attempts, want)
		}
	})

	t.Run("domain reorders by client family", func(t *testing.T) {
		stubLookupIPAddr(t, testPublicV6, testPublicV4)
		d := &probeNetDialer{fail: neverFail}
		if _, err := dialOutbound(t.Context(), d, "tcp", "example.com:443", v4); err != nil {
			t.Fatalf("dialOutbound: %v", err)
		}
		want := []string{"tcp4 " + testPublicV4 + ":443"}
		if !slices.Equal(d.attempts, want) {
			t.Errorf("attempts = %v, want %v", d.attempts, want)
		}
	})

	t.Run("ipv6 client keeps ipv6 first", func(t *testing.T) {
		stubLookupIPAddr(t, testPublicV6, testPublicV4)
		d := &probeNetDialer{fail: neverFail}
		if _, err := dialOutbound(t.Context(), d, "tcp", "example.com:443", v6); err != nil {
			t.Fatalf("dialOutbound: %v", err)
		}
		want := []string{"tcp6 [" + testPublicV6 + "]:443"}
		if !slices.Equal(d.attempts, want) {
			t.Errorf("attempts = %v, want %v", d.attempts, want)
		}
	})

	t.Run("icmp network is concretized per family", func(t *testing.T) {
		d := &probeNetDialer{fail: neverFail}
		if _, err := dialOutbound(t.Context(), d, "ip", testPublicV6, v4); err != nil {
			t.Fatalf("dialOutbound: %v", err)
		}
		// ICMP 目标没有端口时候选端口为 0，网络名同样按目标族具体化。
		want := []string{"ip6 [2606:2800:220:1:248:1893:25c8:1946]:0"}
		if !slices.Equal(d.attempts, want) {
			t.Errorf("attempts = %v, want %v", d.attempts, want)
		}
	})

	t.Run("without preference the target is dialed unchanged", func(t *testing.T) {
		d := &probeNetDialer{fail: neverFail}
		if _, err := dialOutbound(t.Context(), d, "tcp", "example.com:443", netip.Addr{}); err != nil {
			t.Fatalf("dialOutbound: %v", err)
		}
		want := []string{"tcp example.com:443"}
		if !slices.Equal(d.attempts, want) {
			t.Errorf("attempts = %v, want %v", d.attempts, want)
		}
	})

	t.Run("resolution failure falls back to the system resolver", func(t *testing.T) {
		prev := lookupIPAddr
		lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
			return nil, errors.New("dns boom")
		}
		t.Cleanup(func() { lookupIPAddr = prev })

		d := &probeNetDialer{fail: neverFail}
		if _, err := dialOutbound(t.Context(), d, "tcp", "example.com:443", v4); err != nil {
			t.Fatalf("dialOutbound: %v", err)
		}
		want := []string{"tcp example.com:443"}
		if !slices.Equal(d.attempts, want) {
			t.Errorf("attempts = %v, want the unresolved target %v", d.attempts, want)
		}
	})

	t.Run("multiple candidates fall through to the next one", func(t *testing.T) {
		stubLookupIPAddr(t, testPublicV6, testPublicV4)
		d := &probeNetDialer{fail: func(target string) bool {
			return target == "["+testPublicV6+"]:443"
		}}
		if _, err := dialOutbound(t.Context(), d, "tcp", "example.com:443", v6); err != nil {
			t.Fatalf("dialOutbound: %v", err)
		}
		// 每个候选用自己的地址族拨号：回退到 IPv4 候选时网络名也随之变成 tcp4。
		want := []string{"tcp6 [" + testPublicV6 + "]:443", "tcp4 " + testPublicV4 + ":443"}
		if !slices.Equal(d.attempts, want) {
			t.Errorf("attempts = %v, want %v", d.attempts, want)
		}
	})

	t.Run("client disconnect aborts the candidate walk", func(t *testing.T) {
		stubLookupIPAddr(t, testPublicV6, testPublicV4)
		ctx, cancel := context.WithCancel(t.Context())
		d := &probeNetDialer{fail: func(target string) bool {
			if target == "["+testPublicV6+"]:443" {
				cancel()
				return true
			}
			return false
		}}
		if _, err := dialOutbound(ctx, d, "tcp", "example.com:443", v6); err == nil {
			t.Fatal("dialOutbound should return the failure once the client is gone")
		}
		if len(d.attempts) != 1 {
			t.Errorf("attempts = %v, want only the first candidate", d.attempts)
		}
	})
}

type stubConn struct {
	closed chan struct{}
	once   sync.Once
	remote net.Addr
}

func newStubConn(remote net.Addr) *stubConn {
	return &stubConn{closed: make(chan struct{}), remote: remote}
}

func (c *stubConn) Read(p []byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *stubConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *stubConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *stubConn) LocalAddr() net.Addr { return &net.TCPAddr{} }

func (c *stubConn) RemoteAddr() net.Addr { return c.remote }

func (c *stubConn) SetDeadline(t time.Time) error { return nil }

func (c *stubConn) SetReadDeadline(t time.Time) error { return nil }

func (c *stubConn) SetWriteDeadline(t time.Time) error { return nil }

// isClosed 报告该 stub 是否已被调用 Close。
func (c *stubConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func TestTCPHandler_CancelReadOnIdleTimeout(t *testing.T) {
	h := newTCPHandler(150*time.Millisecond, 5*time.Second, nil)
	// 一个静默对端：stub 接受写入但从不产生数据，使用公网远端地址
	// 以便通过拨号后的 SSRF 防护。
	stub := newStubConn(&net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	h.dialContext = func(context.Context, string, string) (net.Conn, error) { return stub, nil }

	sk, err := crypto.NewStreamKeys(
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 16),
		sharedconfig.EndpointTCP,
	)
	if err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	dr, err := sk.NewReader(pr, crypto.DirS2C, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	s2cWriter, err := sk.NewWriter(io.Discard, crypto.DirS2C, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	s2c := shaper.New(s2cWriter, shaper.Config{})

	var cancelled atomic.Bool
	start := time.Now()
	err = h.Handle(context.Background(), dr, s2c, "8.8.8.8:53", func() { cancelled.Store(true) })
	if err == nil {
		t.Fatal("Handle should return an error on idle timeout")
	}
	if !cancelled.Load() {
		t.Fatal("cancelRead should be invoked when the relay terminates")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("Handle took too long to return")
	}
	_ = pw.Close()
}
