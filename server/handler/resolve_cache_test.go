package handler

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
)

// newTestResolveCache 固定测试用的 TTL；需要断言过期的用例再覆写 c.ttl。
func newTestResolveCache(resolve func(context.Context, string) ([]netip.Addr, error)) *resolveCache {
	return newResolveCache(resolve, time.Minute)
}

func TestResolveCacheReusesResult(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	c := newTestResolveCache(func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	})

	for range 3 {
		addrs, err := c.lookup(context.Background(), "example.com:443")
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if len(addrs) != 1 {
			t.Fatalf("addrs = %v, want one address", addrs)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("resolve calls = %d, want 1 (cached)", got)
	}
}

func TestResolveCacheExpires(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	c := newTestResolveCache(func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	})
	c.ttl = 5 * time.Millisecond

	if _, err := c.lookup(context.Background(), "example.com:443"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	time.Sleep(15 * time.Millisecond)
	if _, err := c.lookup(context.Background(), "example.com:443"); err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("resolve calls = %d, want 2 (entry expired)", got)
	}
}

func TestResolveCacheSkipsLiteralIP(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	c := newTestResolveCache(func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	})

	for range 2 {
		if _, err := c.lookup(context.Background(), "1.1.1.1:443"); err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("resolve calls = %d, want 2 (literal IPs bypass the cache)", got)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) != 0 {
		t.Errorf("cache entries = %d, want 0", len(c.entries))
	}
}

func TestResolveCacheDoesNotCacheErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("resolve failed")
	var calls atomic.Int64
	c := newTestResolveCache(func(context.Context, string) ([]netip.Addr, error) {
		if calls.Add(1) == 1 {
			return nil, wantErr
		}
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	})

	if _, err := c.lookup(context.Background(), "example.com:443"); !errors.Is(err, wantErr) {
		t.Fatalf("first lookup error = %v, want %v", err, wantErr)
	}
	addrs, err := c.lookup(context.Background(), "example.com:443")
	if err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("addrs = %v, want one address", addrs)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("resolve calls = %d, want 2 (errors are not cached)", got)
	}
}

func TestResolveCacheCoalescesConcurrentMisses(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	c := newTestResolveCache(func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		time.Sleep(30 * time.Millisecond)
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	})

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := c.lookup(context.Background(), "example.com:443"); err != nil {
				t.Errorf("lookup: %v", err)
			}
		})
	}
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("resolve calls = %d, want 1 (concurrent misses coalesced)", got)
	}
}

func TestResolveCacheBoundsEntries(t *testing.T) {
	t.Parallel()

	c := newTestResolveCache(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	})
	c.max = 4

	for i := range 10 {
		if _, err := c.lookup(context.Background(), fmt.Sprintf("host%d.example.com:443", i)); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > c.max {
		t.Errorf("cache entries = %d, want <= %d", len(c.entries), c.max)
	}
}

func TestResolveCacheKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		target string
		key    string
		ok     bool
	}{
		{"example.com:443", "example.com", true},
		{"example.com", "example.com", true},
		{"1.1.1.1:443", "", false},
		{"1.1.1.1", "", false},
		{"[2001:db8::1]:443", "", false},
		{"2001:db8::1", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		key, ok := resolveCacheKey(tt.target)
		if key != tt.key || ok != tt.ok {
			t.Errorf("resolveCacheKey(%q) = (%q, %v), want (%q, %v)", tt.target, key, ok, tt.key, tt.ok)
		}
	}
}

// TestNewProxyHandlerResolveCacheTTL 固定缓存时长跟随服务端配置的基础超时（2×base），
// 未配置时用默认超时，而不是某个写死的秒数。
func TestNewProxyHandlerResolveCacheTTL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		base time.Duration
		want time.Duration
	}{
		{"显式基础超时", 7 * time.Second, 14 * time.Second},
		{"未配置用默认超时", 0, 2 * time.Duration(config.DefaultTimeout) * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := NewProxyHandler(ProxyHandlerConfig{Timeouts: config.Timeouts{Base: tt.base}})
			if h.deps.resolveCache == nil {
				t.Fatal("expected a resolve cache")
			}
			if got := h.deps.resolveCache.ttl; got != tt.want {
				t.Errorf("resolve cache TTL = %v, want %v", got, tt.want)
			}
		})
	}
}
