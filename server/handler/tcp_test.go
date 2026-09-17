package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
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

// stubLookupNetIP 替换包内的解析函数，使地址族偏好的解析不依赖真实 DNS。
func stubLookupNetIP(t *testing.T, byFamily map[string][]string) {
	t.Helper()
	prev := lookupNetIP
	lookupNetIP = func(_ context.Context, family, host string) ([]netip.Addr, error) {
		addrs := byFamily[family]
		if len(addrs) == 0 {
			return nil, fmt.Errorf("no %s address for %s", family, host)
		}
		out := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
	t.Cleanup(func() { lookupNetIP = prev })
}

// TestPreferredTarget 覆盖域名目标的地址族偏好：只有"有偏好 + 域名的目标 +
// 该族有地址"时才改写目标，其余情况一律返回空串交回系统解析器。
func TestPreferredTarget(t *testing.T) {
	v4 := netip.MustParseAddr(testPublicV4)
	v6 := netip.MustParseAddr(testPublicV6)

	tests := []struct {
		name   string
		target string
		prefer netip.Addr
		stub   map[string][]string
		want   string
	}{
		{name: "没有偏好", target: "example.com:443", want: ""},
		{name: "字面 IPv4 目标的族由目标自身决定", target: testPublicV4 + ":443", prefer: v6, want: ""},
		{name: "字面 IPv6 目标的族由目标自身决定", target: "[" + testPublicV6 + "]:443", prefer: v4, want: ""},
		{name: "没有端口", target: testPublicV6, prefer: v4, want: ""},
		{name: "v4 客户端取 A 记录", target: "example.com:443", prefer: v4,
			stub: map[string][]string{"ip4": {testPublicV4}}, want: testPublicV4 + ":443"},
		{name: "v6 客户端取 AAAA 记录", target: "example.com:443", prefer: v6,
			stub: map[string][]string{"ip6": {testPublicV6}}, want: "[" + testPublicV6 + "]:443"},
		{name: "首选族没有地址时退回系统解析", target: "example.com:443", prefer: v4,
			stub: map[string][]string{"ip6": {testPublicV6}}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.stub != nil {
				stubLookupNetIP(t, tt.stub)
			}
			if got := preferredTarget(t.Context(), tt.target, tt.prefer); got != tt.want {
				t.Fatalf("preferredTarget(%q, %v) = %q, want %q", tt.target, tt.prefer, got, tt.want)
			}
		})
	}
}

// TestDialOutbound 用真实的本地监听覆盖拨号本身：没有偏好时按目标原文拨号，
// 有偏好时拨到首选族解析出的地址，客户端中途离开时标记为 errClientGone。
func TestDialOutbound(t *testing.T) {
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
	v4 := netip.MustParseAddr(testPublicV4)

	t.Run("没有偏好时按目标原文拨号", func(t *testing.T) {
		conn, err := dialOutbound(t.Context(), dialer, "tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dialOutbound: %v", err)
		}
		_ = conn.Close()
	})

	t.Run("有偏好时拨到首选族解析出的地址", func(t *testing.T) {
		stubLookupNetIP(t, map[string][]string{"ip4": {"127.0.0.1"}})
		target := fmt.Sprintf("example.com:%d", ln.Addr().(*net.TCPAddr).Port)

		conn, err := dialOutbound(withPreferredFamily(t.Context(), v4), dialer, "tcp", target)
		if err != nil {
			t.Fatalf("dialOutbound: %v", err)
		}
		defer conn.Close() //nolint:errcheck
		if got := conn.RemoteAddr().String(); got != ln.Addr().String() {
			t.Errorf("dialed %v, want the listener %v", got, ln.Addr())
		}
	})

	t.Run("客户端已离开", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		if _, err := dialOutbound(ctx, dialer, "tcp", testPublicV4+":443"); !errors.Is(err, errClientGone) {
			t.Fatalf("dialOutbound = %v, want errClientGone once the caller's context is gone", err)
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
