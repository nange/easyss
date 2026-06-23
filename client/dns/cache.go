package dns

import (
	"github.com/coocood/freecache"
	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/stats"
)

const (
	cacheSize   = 2 * 1024 * 1024
	maxCacheTTL = 2 * 60 * 60
	minCacheTTL = 60
)

// Cache stores DNS query results in two separate caches: one for proxied
// results and one for direct (non-proxied) results.
type Cache struct {
	proxied *freecache.Cache
	direct  *freecache.Cache
}

// NewCache creates a new DNS cache with separate storage for proxied and direct results.
func NewCache() *Cache {
	return &Cache{
		proxied: freecache.NewCache(cacheSize),
		direct:  freecache.NewCache(cacheSize),
	}
}

// Get retrieves a cached DNS message by name and query type.
// If isDirect is true, the direct cache is queried; otherwise the proxied cache.
func (c *Cache) Get(name, qtype string, isDirect bool) *dns.Msg {
	cache := c.proxied
	if isDirect {
		cache = c.direct
	}
	v, err := cache.Get([]byte(name + qtype))
	if err != nil || len(v) == 0 {
		stats.RecordDNSCacheMiss()
		return nil
	}
	msg := &dns.Msg{}
	if err := msg.Unpack(v); err != nil {
		stats.RecordDNSCacheMiss()
		return nil
	}
	stats.RecordDNSCacheHit()
	return msg
}

// Set stores a DNS message in the appropriate cache using DNS TTL.
// Only A and AAAA records are cached. If isDirect is true, the direct cache is used.
func (c *Cache) Set(msg *dns.Msg, isDirect bool) error {
	if msg == nil || len(msg.Question) == 0 {
		return nil
	}
	q := msg.Question[0]
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		v, err := msg.Pack()
		if err != nil {
			return err
		}
		key := []byte(q.Name + dns.TypeToString[q.Qtype])
		ttl := dnsCacheTTL(msg)
		if isDirect {
			return c.direct.Set(key, v, ttl)
		}
		return c.proxied.Set(key, v, ttl)
	}
	return nil
}

func dnsCacheTTL(msg *dns.Msg) int {
	ttl := uint32(maxCacheTTL)
	for _, rr := range msg.Answer {
		if rr == nil || rr.Header() == nil {
			continue
		}
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	if ttl == 0 || ttl > maxCacheTTL {
		ttl = maxCacheTTL
	}
	if ttl < minCacheTTL {
		ttl = minCacheTTL
	}
	return int(ttl)
}
