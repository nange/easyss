package handler

import (
	"sync"
	"time"

	"github.com/coocood/freecache"
)

const (
	// saltCacheSize 是 freecache 的容量（字节数，约 8MB，可容纳数万个条目）。
	// 条目是 1 字节的值，键为 endpoint 加 22 字符的 base64url salt。
	saltCacheSize = 8 * 1024 * 1024

	// saltCacheTTL 是 salt 在缓存中留存时长的上限。
	// 只要记录可能被重新投递，重放的 bootstrap 记录就必须被拒绝，
	// 因此该 TTL 刻意远大于任何流的生命周期：在两个流上复用同一个 salt
	// 会复用相同的会话密钥和 nonce 计数器（DeriveSessionKeys 不包含
	// endpoint，且每个流的 CounterNonce 都从零开始），
	// 这将导致 GCM 密钥流复用的灾难。
	//
	// 实际的重放窗口是 LRU 驻留时间，而不是这个 TTL：freecache 受容量限制
	// （saltCacheSize），在持续高流速率下，一个被合法接受的 salt 可能在
	// 24 小时之前很久就被逐出，之后它的重放会再次被接受。要弥合这个缺口，
	// 需要的是带显式清扫的 TTL 受限 map，而不是容量受限的缓存。
	saltCacheTTL = 24 * time.Hour
)

// saltCache 记录已被服务器接受的 bootstrap salt。每个流都使用全新的随机
// salt（16 字节，通过 x-es 头以明文传输），因此被重放的 bootstrap 记录
// 必然携带服务器已经见过的 salt。拒绝重复的 salt 因此可以抵御重放攻击；
// 否则每次重放都会让服务器重新拨号目标并重新投递第一个数据包。
//
// 键把 salt 绑定到 endpoint，这样同一个 salt 出现在不同 endpoint 上时
// 不会被误判为重放（按 endpoint 区分的 AAD 本来就使这样的记录无法解密，
// 但一个看起来有效的请求也不应烧掉另一个 endpoint 的 salt 条目）。
type saltCache struct {
	mu    sync.Mutex
	cache *freecache.Cache
}

func newSaltCache() *saltCache {
	return &saltCache{cache: freecache.NewCache(saltCacheSize)}
}

// MarkSeen 记录 endpoint+saltB64，并报告它是否已存在。返回的 bool 在 salt
// 之前已被见过时为 true，即该请求是重放，必须被拒绝。
//
// 互斥锁使检查-设置具有原子性：freecache 的 Get/Set 各自是线程安全的，
// 但如果没有锁，两个并发重复请求可能都在任一 Set 执行之前通过 Get，
// 导致两个请求都被接受。
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
