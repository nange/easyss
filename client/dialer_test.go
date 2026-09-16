package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/router"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/xjasonlyu/tun2socks/v2/dialer"
)

func TestIsInterfaceStaleError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"enetdown", syscall.ENETDOWN, true},
		{"enodev", syscall.ENODEV, true},
		{"enetunreach", syscall.ENETUNREACH, true},
		{"ehostunreach", syscall.EHOSTUNREACH, true},
		{"einval", syscall.EINVAL, true},
		{"refused", syscall.ECONNREFUSED, false},
		{"timeout", context.DeadlineExceeded, false},
		{"wrapped", fmt.Errorf("dial tcp: %w", syscall.ENETDOWN), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isInterfaceStaleError(c.err); got != c.want {
				t.Fatalf("isInterfaceStaleError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestRefreshDirectDialer(t *testing.T) {
	orig := detectDialIface
	t.Cleanup(func() { detectDialIface = orig })

	c := &Client{}
	c.bound.Store(boundIface{name: "en0", index: 4})
	c.dialer.Store(dialer.New())

	en1 := &net.Interface{Index: 7, Name: "en1", Flags: net.FlagUp}

	t.Run("interface changed", func(t *testing.T) {
		detectDialIface = func() (*net.Interface, error) { return en1, nil }
		if !c.refreshDirectDialer() {
			t.Fatal("expected refresh to replace the dialer")
		}
		got, _ := c.bound.Load().(boundIface)
		if got.name != "en1" || got.index != 7 {
			t.Fatalf("bound = %+v, want en1/index 7", got)
		}
		if c.dialer.Load() == nil {
			t.Fatal("dialer should not be nil after refresh")
		}
	})

	t.Run("unchanged interface", func(t *testing.T) {
		detectDialIface = func() (*net.Interface, error) { return en1, nil }
		if c.refreshDirectDialer() {
			t.Fatal("expected no refresh for the same interface")
		}
	})

	t.Run("detection failure keeps old dialer", func(t *testing.T) {
		detectDialIface = func() (*net.Interface, error) { return nil, errors.New("no route") }
		if c.refreshDirectDialer() {
			t.Fatal("expected no refresh on detection failure")
		}
		got, _ := c.bound.Load().(boundIface)
		if got.name != "en1" {
			t.Fatalf("bound = %+v, want previous en1 kept", got)
		}
	})
}

// newTestClient 构建一个最小化的 Client，带 router，并通过 tunEnabled 切换 TUN 模式。
func newTestClient(t *testing.T, tunEnabled bool) *Client {
	t.Helper()

	cfg := &config.ClientConfig{}
	cfg.Local.EnableTun2socks = tunEnabled

	rt, err := router.New(router.Config{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	c := &Client{cfg: cfg, router: rt}
	c.bound.Store(boundIface{name: "en0", index: 4})
	c.dialer.Store(dialer.New())
	return c
}

func TestDialWithConfigRefreshesAndRetriesOnStaleError(t *testing.T) {
	origDetect := detectDialIface
	origBound := boundDialContext
	t.Cleanup(func() {
		detectDialIface = origDetect
		boundDialContext = origBound
	})

	c := newTestClient(t, true)

	// 我们"休眠"期间接口发生了变化。
	detectDialIface = func() (*net.Interface, error) {
		return &net.Interface{Index: 9, Name: "en9", Flags: net.FlagUp}, nil
	}

	calls := 0
	boundDialContext = func(_ *Client, ctx context.Context, network, addr string) (net.Conn, error) {
		calls++
		if calls == 1 {
			return nil, syscall.ENETDOWN
		}
		return &net.TCPConn{}, nil
	}

	conn, err := c.dialWithConfig(context.Background(), "tcp", "1.2.3.4:80")
	if err != nil {
		t.Fatalf("dialWithConfig: %v", err)
	}
	if conn == nil {
		t.Fatal("expected a connection after the refresh retry")
	}
	if calls != 2 {
		t.Fatalf("bound dial calls = %d, want 2 (fail + retry)", calls)
	}
	got, _ := c.bound.Load().(boundIface)
	if got.name != "en9" || got.index != 9 {
		t.Fatalf("bound = %+v, want refreshed to en9/index 9", got)
	}
}

func TestDialWithConfigNoRetryOnNonStaleError(t *testing.T) {
	origDetect := detectDialIface
	origBound := boundDialContext
	t.Cleanup(func() {
		detectDialIface = origDetect
		boundDialContext = origBound
	})

	c := newTestClient(t, true)

	detectDialIface = func() (*net.Interface, error) {
		return &net.Interface{Index: 9, Name: "en9", Flags: net.FlagUp}, nil
	}

	calls := 0
	boundDialContext = func(_ *Client, ctx context.Context, network, addr string) (net.Conn, error) {
		calls++
		return nil, syscall.ECONNREFUSED
	}

	conn, err := c.dialWithConfig(context.Background(), "tcp", "1.2.3.4:80")
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("err = %v, want ECONNREFUSED", err)
	}
	if conn != nil {
		t.Fatal("expected nil connection")
	}
	if calls != 1 {
		t.Fatalf("bound dial calls = %d, want 1 (no retry)", calls)
	}
	got, _ := c.bound.Load().(boundIface)
	if got.name != "en0" {
		t.Fatalf("bound = %+v, want previous en0 kept", got)
	}
}

func TestDialWithConfigNoRefreshWhenBindingUnchanged(t *testing.T) {
	origDetect := detectDialIface
	origBound := boundDialContext
	t.Cleanup(func() {
		detectDialIface = origDetect
		boundDialContext = origBound
	})

	c := newTestClient(t, true)

	// 与启动时记录的接口相同：刷新不得替换它，因此重试仍使用同一个 dialer。
	detectDialIface = func() (*net.Interface, error) {
		return &net.Interface{Index: 4, Name: "en0", Flags: net.FlagUp}, nil
	}

	calls := 0
	boundDialContext = func(_ *Client, ctx context.Context, network, addr string) (net.Conn, error) {
		calls++
		if calls == 1 {
			return nil, syscall.ENETDOWN
		}
		return &net.TCPConn{}, nil
	}

	_, err := c.dialWithConfig(context.Background(), "tcp", "1.2.3.4:80")
	if !errors.Is(err, syscall.ENETDOWN) {
		t.Fatalf("err = %v, want ENETDOWN from the first dial", err)
	}
	if calls != 1 {
		t.Fatalf("bound dial calls = %d, want 1 (refresh found no change, no retry)", calls)
	}
}

func TestDialWithConfigPlainPathWhenTunDisabled(t *testing.T) {
	origBound := boundDialContext
	t.Cleanup(func() { boundDialContext = origBound })

	c := newTestClient(t, false)

	called := false
	boundDialContext = func(_ *Client, ctx context.Context, network, addr string) (net.Conn, error) {
		called = true
		return nil, errors.New("must not be used when TUN is disabled")
	}

	// 普通路径使用真实 socket：被拒绝的回环拨号既快又确定。
	_, err := c.dialWithConfig(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected connection refused")
	}
	if called {
		t.Fatal("bound dial must not be used when TUN is disabled")
	}
}

func TestRefreshDirectDialerIgnoresTunDevice(t *testing.T) {
	orig := detectDialIface
	t.Cleanup(func() { detectDialIface = orig })

	c := newTestClient(t, true)
	detectDialIface = func() (*net.Interface, error) {
		// TUN 激活期间，Windows/Linux 的路由探测会解析到 TUN 设备本身。
		// 绑定到它会让每次拨号都回环进 TUN 设备。
		return &net.Interface{Index: 10, Name: sharedconfig.DefaultTunDeviceName, Flags: net.FlagUp}, nil
	}

	if c.refreshDirectDialer() {
		t.Fatal("expected no refresh when the probe resolves to the TUN device")
	}
	got, _ := c.bound.Load().(boundIface)
	if got.name != "en0" || got.index != 4 {
		t.Fatalf("bound = %+v, want previous en0/index 4 kept", got)
	}
}

func TestRefreshDirectDialerIgnoresCustomTunDeviceName(t *testing.T) {
	orig := detectDialIface
	t.Cleanup(func() { detectDialIface = orig })

	c := newTestClient(t, true)
	c.cfg.Local.TunConfig = json.RawMessage(`{"device":"my-tun9"}`)

	t.Run("custom tun device name is rejected", func(t *testing.T) {
		detectDialIface = func() (*net.Interface, error) {
			return &net.Interface{Index: 21, Name: "my-tun9", Flags: net.FlagUp}, nil
		}
		if c.refreshDirectDialer() {
			t.Fatal("expected no refresh for the custom-named TUN device")
		}
		got, _ := c.bound.Load().(boundIface)
		if got.name != "en0" {
			t.Fatalf("bound = %+v, want previous en0 kept", got)
		}
	})

	t.Run("unrelated interface still refreshes", func(t *testing.T) {
		detectDialIface = func() (*net.Interface, error) {
			return &net.Interface{Index: 22, Name: "en7", Flags: net.FlagUp}, nil
		}
		if !c.refreshDirectDialer() {
			t.Fatal("expected refresh for a physical interface change")
		}
		got, _ := c.bound.Load().(boundIface)
		if got.name != "en7" || got.index != 22 {
			t.Fatalf("bound = %+v, want en7/index 22", got)
		}
	})
}

func TestDialWithConfigNoRetryWhenRefreshDetectsTun(t *testing.T) {
	origDetect := detectDialIface
	origBound := boundDialContext
	t.Cleanup(func() {
		detectDialIface = origDetect
		boundDialContext = origBound
	})

	c := newTestClient(t, true)

	// 拨号因接口过期错误失败，但探测解析到 TUN 设备（TUN 已激活）：刷新必须保留旧的绑定
	// 且不重试，因为经由 TUN 设备重试会形成回环。
	detectDialIface = func() (*net.Interface, error) {
		return &net.Interface{Index: 10, Name: sharedconfig.DefaultTunDeviceName, Flags: net.FlagUp}, nil
	}

	calls := 0
	boundDialContext = func(_ *Client, ctx context.Context, network, addr string) (net.Conn, error) {
		calls++
		return nil, syscall.ENETDOWN
	}

	conn, err := c.dialWithConfig(context.Background(), "tcp", "1.2.3.4:80")
	if !errors.Is(err, syscall.ENETDOWN) {
		t.Fatalf("err = %v, want ENETDOWN from the first dial", err)
	}
	if conn != nil {
		t.Fatal("expected nil connection")
	}
	if calls != 1 {
		t.Fatalf("bound dial calls = %d, want 1 (no retry through the TUN device)", calls)
	}
	got, _ := c.bound.Load().(boundIface)
	if got.name != "en0" {
		t.Fatalf("bound = %+v, want previous en0 kept", got)
	}
}

func TestStartupDialIface(t *testing.T) {
	tunIface := &net.Interface{Index: 10, Name: sharedconfig.DefaultTunDeviceName, Flags: net.FlagUp}

	t.Run("probe returns physical interface", func(t *testing.T) {
		orig := detectDialIface
		t.Cleanup(func() { detectDialIface = orig })
		detectDialIface = func() (*net.Interface, error) {
			return &net.Interface{Index: 4, Name: "en0", Flags: net.FlagUp}, nil
		}

		c := newTestClient(t, true)
		iface := c.startupDialIface()
		if iface == nil || iface.Name != "en0" {
			t.Fatalf("startupDialIface = %v, want en0", iface)
		}
	})

	t.Run("probe returns TUN device, falls back to physical interface", func(t *testing.T) {
		origDetect := detectDialIface
		origList := listInterfaces
		origAddrs := ifaceAddrs
		t.Cleanup(func() {
			detectDialIface = origDetect
			listInterfaces = origList
			ifaceAddrs = origAddrs
		})
		detectDialIface = func() (*net.Interface, error) { return tunIface, nil }
		listInterfaces = func() ([]net.Interface, error) {
			return []net.Interface{
				{Index: 10, Name: sharedconfig.DefaultTunDeviceName, Flags: net.FlagUp},
				{Index: 7, Name: "en0", Flags: net.FlagUp},
			}, nil
		}
		ifaceAddrs = func(iface *net.Interface) ([]net.Addr, error) {
			if iface.Name != "en0" {
				return nil, errors.New("no addrs")
			}
			return []net.Addr{&net.IPNet{IP: net.IPv4(192, 168, 1, 5), Mask: net.CIDRMask(24, 32)}}, nil
		}

		c := newTestClient(t, true)
		iface := c.startupDialIface()
		if iface == nil || iface.Name != "en0" || iface.Index != 7 {
			t.Fatalf("startupDialIface = %v, want fallback en0/index 7", iface)
		}
	})

	t.Run("probe fails and no usable interface, returns nil", func(t *testing.T) {
		origDetect := detectDialIface
		origList := listInterfaces
		t.Cleanup(func() {
			detectDialIface = origDetect
			listInterfaces = origList
		})
		detectDialIface = func() (*net.Interface, error) { return nil, errors.New("no route") }
		listInterfaces = func() ([]net.Interface, error) {
			return []net.Interface{{Index: 10, Name: sharedconfig.DefaultTunDeviceName, Flags: net.FlagUp}}, nil
		}

		c := newTestClient(t, true)
		if iface := c.startupDialIface(); iface != nil {
			t.Fatalf("startupDialIface = %v, want nil (unbound fallback)", iface)
		}
	})
}

func TestInitDirectDialerUnsupportedPlatform(t *testing.T) {
	orig := ifaceBindUnsupported
	t.Cleanup(func() { ifaceBindUnsupported = orig })
	ifaceBindUnsupported = func() bool { return true }

	c := &Client{}
	c.bound.Store(boundIface{name: "en0", index: 4})

	if name := c.initDirectDialer(); name != "" {
		t.Fatalf("initDirectDialer = %q, want unbound", name)
	}
	if c.dialer.Load() == nil {
		t.Fatal("dialer should not be nil on the unbound path")
	}
	got, _ := c.bound.Load().(boundIface)
	if got.name != "en0" || got.index != 4 {
		t.Fatalf("bound = %+v, want previous en0/index 4 kept", got)
	}
}

func TestInitDirectDialerBindsWhenSupported(t *testing.T) {
	orig := ifaceBindUnsupported
	origDetect := detectDialIface
	t.Cleanup(func() {
		ifaceBindUnsupported = orig
		detectDialIface = origDetect
	})
	ifaceBindUnsupported = func() bool { return false }
	detectDialIface = func() (*net.Interface, error) {
		return &net.Interface{Index: 7, Name: "en0", Flags: net.FlagUp}, nil
	}

	c := &Client{}
	if name := c.initDirectDialer(); name != "en0" {
		t.Fatalf("initDirectDialer = %q, want en0", name)
	}
	got, _ := c.bound.Load().(boundIface)
	if got.name != "en0" || got.index != 7 {
		t.Fatalf("bound = %+v, want en0/index 7", got)
	}
}

func TestInitDirectDialerUnboundOnDetectionFailure(t *testing.T) {
	orig := ifaceBindUnsupported
	origDetect := detectDialIface
	origList := listInterfaces
	t.Cleanup(func() {
		ifaceBindUnsupported = orig
		detectDialIface = origDetect
		listInterfaces = origList
	})
	ifaceBindUnsupported = func() bool { return false }
	detectDialIface = func() (*net.Interface, error) { return nil, errors.New("no route") }
	listInterfaces = func() ([]net.Interface, error) { return nil, nil }

	c := &Client{}
	if name := c.initDirectDialer(); name != "" {
		t.Fatalf("initDirectDialer = %q, want unbound", name)
	}
	if c.dialer.Load() == nil {
		t.Fatal("dialer should not be nil on the unbound path")
	}
	if _, ok := c.bound.Load().(boundIface); ok {
		t.Fatal("expected no binding recorded")
	}
}

func TestRefreshDirectDialerSkipsOnUnsupportedPlatform(t *testing.T) {
	orig := ifaceBindUnsupported
	t.Cleanup(func() { ifaceBindUnsupported = orig })
	ifaceBindUnsupported = func() bool { return true }

	c := &Client{}
	c.bound.Store(boundIface{name: "en0", index: 4})
	c.dialer.Store(dialer.New())

	if c.refreshDirectDialer() {
		t.Fatal("expected no refresh on an unsupported platform")
	}
	got, _ := c.bound.Load().(boundIface)
	if got.name != "en0" || got.index != 4 {
		t.Fatalf("bound = %+v, want previous en0/index 4 kept", got)
	}
}
