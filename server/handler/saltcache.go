package handler

import (
	"sync"
	"time"

	"github.com/coocood/freecache"
)

const (
	// saltCacheSize 是 freecache 的容量（字节数，约 8MB，可容纳数万个条目）。
	saltCacheSize = 8 * 1024 * 1024

	// 必须远大于任何流的生命周期：复用同一 salt 会复用相同的会话密钥与 nonce 计数器
	// （DeriveSessionKeys 不含 endpoint），导致 GCM 密钥流复用；实际窗口还受 LRU 驻留限制。
	saltCacheTTL = 24 * time.Hour
)

// saltCache 记录已被服务器接受的 bootstrap salt：每条流都用全新的随机 salt，重放的记录必然
// 携带已见过的 salt。键把 salt 绑定到 endpoint，同一 salt 出现在不同 endpoint 上不会误判为重放。
type saltCache struct {
	mu    sync.Mutex
	cache *freecache.Cache
}

func newSaltCache() *saltCache {
	return &saltCache{cache: freecache.NewCache(saltCacheSize)}
}

// MarkSeen 记录 endpoint+saltB64，返回 true 表示重放、必须拒绝。
// 锁保证检查-设置原子：freecache 的 Get/Set 各自线程安全，但并发重复请求可能都通过 Get。
func (c *saltCache) MarkSeen(endpoint, saltB64 string) bool {
	key := []byte(endpoint + saltB64)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.cache.Get(key); err == nil {
		return true
	}
	_ = c.cache.Set(key, []byte{1}, int(saltCacheTTL.Seconds()))
	return false
}
