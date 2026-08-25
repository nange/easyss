package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/router"
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

// newTestClient builds a minimal Client with a router and TUN mode toggled by
// tunEnabled.
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

	// The interface changed while we were "asleep".
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

	// Same interface as recorded at startup: refresh must not replace it,
	// so the retry uses the same dialer.
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

	// The plain path uses a real socket: a refused loopback dial is fast
	// and deterministic.
	_, err := c.dialWithConfig(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected connection refused")
	}
	if called {
		t.Fatal("bound dial must not be used when TUN is disabled")
	}
}
