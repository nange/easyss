package handler

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// resolveCacheMax 是条目上限：代理面对的目标集合无界，这里只保证内存有界。
const resolveCacheMax = 1024

// resolveCache 缓存 host→addrs，键用 host 而非 host:port：同一主机的不同端口共享一次解析。
// TTL 由调用方给出（服务端取 2×基础超时）。握手期 SSRF 校验与拨号取的是同一批地址，
// 缓存不改变 DNS-rebinding 的判定依据；返回的切片只读，调用方不得改写。
type resolveCache struct {
	resolve func(context.Context, string) ([]netip.Addr, error)
	ttl     time.Duration
	max     int

	mu      sync.Mutex
	entries map[string]resolveEntry
	group   singleflight.Group
}

type resolveEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

func newResolveCache(resolve func(context.Context, string) ([]netip.Addr, error), ttl time.Duration) *resolveCache {
	return &resolveCache{
		resolve: resolve,
		ttl:     ttl,
		max:     resolveCacheMax,
		entries: make(map[string]resolveEntry),
	}
}

func (c *resolveCache) lookup(ctx context.Context, target string) ([]netip.Addr, error) {
	key, ok := resolveCacheKey(target)
	if !ok {
		return c.resolve(ctx, target)
	}

	if addrs, ok := c.load(key); ok {
		return addrs, nil
	}

	// 冷缓存时同一主机的并发流只解析一次：首屏的若干条流否则会同时压满解析器。
	ch := c.group.DoChan(key, func() (any, error) {
		// 解析结果按 key 共享，一个调用方离开不该让其余等待者失败；预算由解析器自己的
		// 3s 兜底给出。
		addrs, err := c.resolve(context.WithoutCancel(ctx), target)
		if err != nil {
			return nil, err
		}
		c.store(key, addrs)
		return addrs, nil
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.([]netip.Addr), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *resolveCache) load(key string) ([]netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.addrs, true
}

func (c *resolveCache) store(key string, addrs []netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		c.evictLocked()
	}
	c.entries[key] = resolveEntry{addrs: addrs, expires: time.Now().Add(c.ttl)}
}

// evictLocked 先清掉过期条目，仍满时淘汰最早到期的一条：过期结果不该把还能用的挤掉，
// 也不需要为命中率引入 LRU 或后台清扫 goroutine。
func (c *resolveCache) evictLocked() {
	now := time.Now()
	var oldestKey string
	var oldest time.Time
	for k, entry := range c.entries {
		if now.After(entry.expires) {
			delete(c.entries, k)
			continue
		}
		if oldestKey == "" || entry.expires.Before(oldest) {
			oldestKey, oldest = k, entry.expires
		}
	}
	if len(c.entries) >= c.max && oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// 字面 IP 不进缓存：它没有解析成本，而且 TUN 模式下目标多是 IP，会把域名条目挤掉。
func resolveCacheKey(target string) (string, bool) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	if host == "" {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", false
	}
	return host, true
}
