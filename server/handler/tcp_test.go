package handler

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
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

// stubResolveHost 替换包内的解析入口，使 SSRF 校验与拨号不依赖真实 DNS。
// 返回的计数器用于断言「一次流只解析一次」：复用握手结果时它必须保持为 0。
func stubResolveHost(t *testing.T, addrs []string, err error) *atomic.Int32 {
	t.Helper()
	calls := &atomic.Int32{}
	prev := resolveHost
	resolveHost = func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		if err != nil {
			return nil, err
		}
		out := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
	t.Cleanup(func() { resolveHost = prev })
	return calls
}

// TestDialCandidates 覆盖 SSRF 校验与拨号候选的构造：候选永远是字面地址
// （域名不会被交给拨号器），任一候选为 LAN 时整个目标被拒绝，且 ctx 中已有
// 握手阶段校验过的地址时不再查 DNS——检查与连接之间没有可供 DNS-rebinding
// 翻转答案的第二次解析。
func TestDialCandidates(t *testing.T) {
	v4 := netip.MustParseAddr(testPublicV4)
	v6 := netip.MustParseAddr(testPublicV6)

	t.Run("字面公网地址", func(t *testing.T) {
		got, err := dialCandidates(t.Context(), testPublicV4+":443")
		if err != nil {
			t.Fatalf("dialCandidates: %v", err)
		}
		if len(got) != 1 || got[0] != v4 {
			t.Fatalf("candidates = %v, want [%v]", got, v4)
		}
	})

	t.Run("字面 LAN 地址被拒绝", func(t *testing.T) {
		_, err := dialCandidates(t.Context(), "127.0.0.1:80")
		if err == nil || !strings.Contains(err.Error(), "ssrf: rejected lan destination") {
			t.Fatalf("dialCandidates = %v, want an ssrf rejection", err)
		}
	})

	t.Run("域名解析到 LAN 被拒绝", func(t *testing.T) {
		stubResolveHost(t, []string{testPublicV4, "10.0.0.1"}, nil)
		_, err := dialCandidates(t.Context(), "example.com:443")
		if err == nil || !strings.Contains(err.Error(), "ssrf: rejected lan destination 10.0.0.1") {
			t.Fatalf("dialCandidates = %v, want a rejection naming the LAN address", err)
		}
	})

	t.Run("解析失败直接返回错误", func(t *testing.T) {
		stubResolveHost(t, nil, errors.New("dns boom"))
		if _, err := dialCandidates(t.Context(), "example.com:443"); err == nil {
			t.Fatal("dialCandidates should report the resolution failure")
		}
	})

	t.Run("优先族排前", func(t *testing.T) {
		stubResolveHost(t, []string{testPublicV6, testPublicV4}, nil)
		ctx := withPreferredFamily(t.Context(), v4)
		got, err := dialCandidates(ctx, "example.com:443")
		if err != nil {
			t.Fatalf("dialCandidates: %v", err)
		}
		if len(got) != 2 || got[0] != v4 || got[1] != v6 {
			t.Fatalf("candidates = %v, want the v4 address first", got)
		}
	})

	t.Run("无偏好保持解析器顺序", func(t *testing.T) {
		stubResolveHost(t, []string{testPublicV6, testPublicV4}, nil)
		got, err := dialCandidates(t.Context(), "example.com:443")
		if err != nil {
			t.Fatalf("dialCandidates: %v", err)
		}
		if len(got) != 2 || got[0] != v6 || got[1] != v4 {
			t.Fatalf("candidates = %v, want the resolver order preserved", got)
		}
	})

	// rebinding 回归：即使此刻的解析会返回 LAN，拨号也只使用握手阶段已经
	// 校验过的地址，因为根本不会再解析。
	t.Run("复用握手结果时不再解析", func(t *testing.T) {
		calls := stubResolveHost(t, []string{"127.0.0.1"}, nil)
		ctx := withResolvedAddrs(t.Context(), []netip.Addr{v4})

		got, err := dialCandidates(ctx, "example.com:443")
		if err != nil {
			t.Fatalf("dialCandidates: %v", err)
		}
		if len(got) != 1 || got[0] != v4 {
			t.Fatalf("candidates = %v, want the pinned %v", got, v4)
		}
		if n := calls.Load(); n != 0 {
			t.Fatalf("the pinned resolution should not be repeated, got %d lookups", n)
		}
	})
}

// TestDialAddr 覆盖拨号地址的拼接：端口字符串原样沿用，无端口的目标（ICMP）
// 拨裸 IP——给原始套接字的目标带上端口会让 net.Dial 直接失败。
func TestDialAddr(t *testing.T) {
	v4 := netip.MustParseAddr(testPublicV4)
	v6 := netip.MustParseAddr(testPublicV6)

	tests := []struct {
		name   string
		addr   netip.Addr
		target string
		want   string
	}{
		{name: "ipv4 带端口", addr: v4, target: "example.com:443", want: testPublicV4 + ":443"},
		{name: "ipv6 带端口", addr: v6, target: "example.com:443", want: "[" + testPublicV6 + "]:443"},
		{name: "无端口保持裸地址", addr: v6, target: testPublicV6, want: testPublicV6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dialAddr(tt.addr, tt.target); got != tt.want {
				t.Fatalf("dialAddr(%v, %q) = %q, want %q", tt.addr, tt.target, got, tt.want)
			}
		})
	}
}

// TestDialAddrs 用真实的本地监听覆盖拨号本身（不经过 LAN 校验，因此 127.0.0.1
// 可以直接使用）：第一个候选失败时回退到下一个，全部失败返回最后一个错误，
// 客户端已离开时标记 errClientGone。
func TestDialAddrs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	dialer := outboundDialer(5*time.Second, 0)
	target := ln.Addr().String()

	t.Run("第一个候选失败时回退", func(t *testing.T) {
		// ::1 上没有监听者，连接会立刻被拒绝；第二个候选才是监听的 127.0.0.1。
		addrs := []netip.Addr{netip.IPv6Loopback(), netip.MustParseAddr("127.0.0.1")}

		conn, err := dialAddrs(t.Context(), dialer, "tcp", target, addrs)
		if err != nil {
			t.Fatalf("dialAddrs: %v", err)
		}
		defer conn.Close() //nolint:errcheck
		if got := conn.RemoteAddr().String(); got != target {
			t.Fatalf("dialed %v, want the listener %v", got, target)
		}
	})

	t.Run("全部候选失败返回最后一个错误", func(t *testing.T) {
		addrs := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		closed, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		target := closed.Addr().String()
		_ = closed.Close()

		if _, err := dialAddrs(t.Context(), dialer, "tcp", target, addrs); err == nil {
			t.Fatal("dialAddrs should return the failure of the last candidate")
		}
	})

	t.Run("客户端已离开", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		addrs := []netip.Addr{netip.MustParseAddr(testPublicV4)}
		if _, err := dialAddrs(ctx, dialer, "tcp", testPublicV4+":443", addrs); !errors.Is(err, errClientGone) {
			t.Fatalf("dialAddrs = %v, want errClientGone once the caller's context is gone", err)
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
