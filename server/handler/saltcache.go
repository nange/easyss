package handler

import (
	"sync"
	"time"

	"github.com/coocood/freecache"
)

const (
	// saltCacheSize is the freecache capacity in bytes (~8MB, tens of
	// thousands of entries). Entries are 1-byte values keyed by the
	// endpoint plus the 22-char base64url salt.
	saltCacheSize = 8 * 1024 * 1024

	// saltCacheTTL bounds how long a salt stays in the cache. A replayed
	// bootstrap record must be rejected for as long as the record could be
	// re-delivered, so the TTL is deliberately far longer than any stream
	// lifetime: reusing the same salt on two streams would reuse the same
	// session keys and nonce counter (DeriveSessionKeys does not include the
	// endpoint, and each stream's CounterNonce starts from zero), which is a
	// GCM keystream-reuse catastrophe. The cache is capacity-bounded by
	// freecache's LRU, so this only bounds how long an evicted salt's replay
	// window stays closed.
	saltCacheTTL = 24 * time.Hour
)

// saltCache records bootstrap salts that have already been accepted by the
// server. Every stream uses a fresh random salt (16 bytes, transmitted in
// plaintext via the x-es header), so a replayed bootstrap record necessarily
// carries a salt the server has already seen. Rejecting duplicate salts
// therefore defeats replay attacks, which would otherwise make the server
// re-dial the target and re-deliver the first packet on every replay.
//
// The key binds the salt to the endpoint so the same salt on a different
// endpoint is not falsely treated as a replay (the per-endpoint AAD makes
// such a record undecryptable anyway, but a valid-looking request must not
// burn the salt entry of another endpoint).
type saltCache struct {
	mu    sync.Mutex
	cache *freecache.Cache
}

func newSaltCache() *saltCache {
	return &saltCache{cache: freecache.NewCache(saltCacheSize)}
}

// MarkSeen records endpoint+saltB64 and reports whether it was already
// present. The returned bool is true when the salt has been seen before,
// i.e. the request is a replay and must be rejected.
//
// The mutex makes the check-and-set atomic: freecache's Get/Set are each
// individually synchronized, but a concurrent duplicate request could
// otherwise pass the Get on both goroutines before either Set runs, and both
// requests would be accepted.
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
