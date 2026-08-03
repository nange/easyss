package handler

import (
	"sync"
	"time"
)

const (
	// handshakeRate is the token refill rate (handshakes per second) allowed
	// per source IP. The salt replay cache already rejects replayed records
	// before any dial happens, so this limiter mainly bounds brute-force
	// handshake attempts that waste decryption CPU. Tuned generously enough
	// not to disturb legit clients behind a shared (NAT) IP.
	handshakeRate = 50.0

	// handshakeBurst is the initial bucket capacity (allowed burst size).
	handshakeBurst = 100

	// ipCleanupThreshold triggers a sweep of idle buckets once the map grows
	// beyond this many distinct source IPs.
	ipCleanupThreshold = 4096

	// ipCleanupTTL is how long a fully-replenished bucket may stay idle
	// before it is dropped.
	ipCleanupTTL = 30 * time.Minute
)

// ipRateLimiter is a simple per-IP token bucket that bounds the rate of
// handshake attempts, mitigating replay storms and resource abuse.
type ipRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*ipTokenBucket
	now     func() time.Time
}

type ipTokenBucket struct {
	tokens float64
	last   time.Time
}

func newIPRateLimiter() *ipRateLimiter {
	return &ipRateLimiter{buckets: make(map[string]*ipTokenBucket), now: time.Now}
}

// Allow reports whether the given IP may perform a handshake right now.
func (l *ipRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.buckets) >= ipCleanupThreshold {
		l.cleanupLocked()
	}

	now := l.now()
	b, ok := l.buckets[ip]
	if !ok {
		// Consume the first token on bucket creation so the total allowed
		// burst equals handshakeBurst.
		l.buckets[ip] = &ipTokenBucket{tokens: handshakeBurst - 1, last: now}
		return true
	}

	b.tokens = min(float64(handshakeBurst), b.tokens+now.Sub(b.last).Seconds()*handshakeRate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// cleanupLocked drops buckets that are fully replenished and have been idle
// for ipCleanupTTL, preventing unbounded growth of the map.
func (l *ipRateLimiter) cleanupLocked() {
	now := l.now()
	for ip, b := range l.buckets {
		if b.tokens >= float64(handshakeBurst) && now.Sub(b.last) > ipCleanupTTL {
			delete(l.buckets, ip)
		}
	}
}
