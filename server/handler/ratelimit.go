package handler

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
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

	// ipCleanupThreshold triggers a sweep of idle entries once the map grows
	// beyond this many distinct source IPs.
	ipCleanupThreshold = 4096

	// ipCleanupTTL is how long an idle limiter entry may stay before it is
	// dropped. Idle for this long the bucket is necessarily full again, so
	// dropping and recreating it loses no state.
	ipCleanupTTL = 30 * time.Minute
)

// ipRateLimiter bounds handshake attempts per source IP using a token bucket
// per IP (golang.org/x/time/rate), mitigating replay storms and resource
// abuse.
type ipRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*ipRateEntry
	now     func() time.Time
}

type ipRateEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter() *ipRateLimiter {
	return &ipRateLimiter{entries: make(map[string]*ipRateEntry), now: time.Now}
}

// Allow reports whether the given IP may perform a handshake right now.
func (l *ipRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.entries) >= ipCleanupThreshold {
		l.cleanupLocked()
	}

	now := l.now()
	e, ok := l.entries[ip]
	if !ok {
		e = &ipRateEntry{lim: rate.NewLimiter(rate.Limit(handshakeRate), handshakeBurst), lastSeen: now}
		l.entries[ip] = e
	}
	e.lastSeen = now
	return e.lim.AllowN(now, 1)
}

// cleanupLocked drops entries idle for ipCleanupTTL, preventing unbounded
// growth of the map.
func (l *ipRateLimiter) cleanupLocked() {
	now := l.now()
	for ip, e := range l.entries {
		if now.Sub(e.lastSeen) > ipCleanupTTL {
			delete(l.entries, ip)
		}
	}
}
