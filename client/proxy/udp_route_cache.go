package proxy

import (
	"sync"

	"github.com/nange/easyss/v3/client/router"
)

// maxUDPRouteCacheEntries 限制按目标缓存的分类结果。UDP 目标可以是任意 IP，必须设上限；
// 超过后整表清空而不是逐条淘汰，避免在热路径上维护 LRU。
const maxUDPRouteCacheEntries = 4096

// udpRouteCache 缓存 ClassifyHost 的结果，规则版本变化时整表失效。UDP 每个数据报都要
// 分类，而 rule.Set 的读锁与 GeoIP 查询不该按包重做。
type udpRouteCache struct {
	mu         sync.Mutex
	generation uint64
	entries    map[string]router.HostClassification
}

func newUDPRouteCache() *udpRouteCache {
	return &udpRouteCache{entries: make(map[string]router.HostClassification)}
}

func (c *udpRouteCache) classify(rt *router.Router, host string) router.HostClassification {
	if rt == nil {
		return rt.ClassifyHost(host)
	}

	generation := rt.RuleGeneration()
	c.mu.Lock()
	if c.generation != generation {
		clear(c.entries)
		c.generation = generation
	}
	if cls, ok := c.entries[host]; ok {
		c.mu.Unlock()
		return cls
	}
	c.mu.Unlock()

	// 分类在锁外做：rule.Set/GeoIP 内部有自己的锁，不能把它们套进缓存锁。
	cls := rt.ClassifyHost(host)

	c.mu.Lock()
	if c.generation == generation {
		if c.entries == nil {
			c.entries = make(map[string]router.HostClassification)
		}
		if len(c.entries) >= maxUDPRouteCacheEntries {
			clear(c.entries)
		}
		c.entries[host] = cls
	}
	c.mu.Unlock()
	return cls
}
