package handler

import (
	"time"

	"github.com/coocood/freecache"
)

const (
	// saltCacheSize is the freecache capacity in bytes (~8MB, tens of
	// thousands of entries). Entries are 1-byte values keyed by the 22-char
	// base64url salt.
	saltCacheSize = 8 * 1024 * 1024

	// saltCacheTTL bounds how long a salt stays in the cache. Streams live
	// far shorter than this, so TTL expiry only bounds memory.
	saltCacheTTL = time.Hour
)

// saltCache records bootstrap salts that have already been accepted by the
// server. Every stream uses a fresh random salt (16 bytes, transmitted in
// plaintext via the x-es header), so a replayed bootstrap record necessarily
// carries a salt the server has already seen. Rejecting duplicate salts
// therefore defeats replay attacks, which would otherwise make the server
// re-dial the target and re-deliver the first packet on every replay.
type saltCache struct {
	cache *freecache.Cache
}

func newSaltCache() *saltCache {
	return &saltCache{cache: freecache.NewCache(saltCacheSize)}
}

// MarkSeen records saltB64 and reports whether it was already present.
// The returned bool is true when the salt has been seen before, i.e. the
// request is a replay and must be rejected.
func (c *saltCache) MarkSeen(saltB64 string) bool {
	key := []byte(saltB64)
	if _, err := c.cache.Get(key); err == nil {
		return true
	}
	_ = c.cache.Set(key, []byte{1}, int(saltCacheTTL.Seconds()))
	return false
}
