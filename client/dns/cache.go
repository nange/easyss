package dns

import (
	"fmt"
	"strings"

	"github.com/coocood/freecache"
	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

const (
	cacheSize   = 2 * 1024 * 1024
	maxCacheTTL = 2 * 60 * 60
	minCacheTTL = 30 * 60
)

// Cache stores DNS query results in two separate caches: one for proxied
// results and one for direct (non-proxied) results.
type Cache struct {
	proxied      *freecache.Cache
	direct       *freecache.Cache
	serverDomain string
}

// NewCache creates a new DNS cache with separate storage for proxied and
// direct results. Entries for serverDomain (usually the proxy server's own
// hostname) are cached without expiration so that a TTL expiry can never
// trigger a burst of concurrent direct queries for it.
func NewCache(serverDomain string) *Cache {
	return &Cache{
		proxied:      freecache.NewCache(cacheSize),
		direct:       freecache.NewCache(cacheSize),
		serverDomain: serverDomain,
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
		ttl := dnsCacheTTL(msg, c.serverDomain)
		if isDirect {
			return c.direct.Set(key, v, ttl)
		}
		return c.proxied.Set(key, v, ttl)
	}
	return nil
}

// dnsCacheTTL returns the cache lifetime in seconds for the given DNS
// message. Entries for the proxy server's own domain never expire (0 means
// forever in freecache); other domains are cached for the minimal answer TTL
// clamped to [minCacheTTL, maxCacheTTL].
func dnsCacheTTL(msg *dns.Msg, serverDomain string) int {
	if serverDomain != "" {
		q := msg.Question[0]
		domain := strings.TrimSuffix(q.Name, ".")
		if strings.EqualFold(domain, serverDomain) {
			return 0
		}
	}
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

// PrePopulate resolves the domain via the given DNS server and stores the
// A and AAAA results in both the direct and proxied caches. This is used
// to pre-seed the cache with the proxy server's IP before TUN routes are
// active, avoiding a DNS deadlock.
// When requireIPv4 is true, the A query must succeed; otherwise either
// A or AAAA success is sufficient.
func (c *Cache) PrePopulate(domain, dnsServer string, requireIPv4 bool) error {
	store := func(msg *dns.Msg) {
		if msg == nil {
			return
		}
		if err := c.Set(msg, true); err != nil {
			log.Warn("[DNS] PrePopulate set direct cache", "domain", domain, "err", err)
		}
		if err := c.Set(msg, false); err != nil {
			log.Warn("[DNS] PrePopulate set proxy cache", "domain", domain, "err", err)
		}
	}

	var ok bool
	var aErr error
	if msgA, err := DNSMsgTypeA(dnsServer, domain); err == nil {
		store(msgA)
		ok = true
	} else {
		aErr = err
		log.Warn("[DNS] PrePopulate type A", "domain", domain, "err", err)
	}

	if msgAAAA, err := DNSMsgTypeAAAA(dnsServer, domain); err == nil {
		store(msgAAAA)
		if !requireIPv4 {
			ok = true
		}
	} else {
		log.Warn("[DNS] PrePopulate type AAAA", "domain", domain, "err", err)
	}

	if !ok {
		if requireIPv4 && aErr != nil {
			return fmt.Errorf("failed to resolve %s A record via %s: %w", domain, dnsServer, aErr)
		}
		return fmt.Errorf("failed to resolve %s via %s", domain, dnsServer)
	}
	return nil
}
