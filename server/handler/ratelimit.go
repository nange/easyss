package handler

import (
	"sync"
	"time"

	"github.com/nange/easyss/v3/log"
	"golang.org/x/time/rate"
)

const (
	// handshakeRate 是每个源 IP 允许的令牌补充速率（每秒握手次数）。
	// salt 重放缓存已经在任何拨号发生之前拒绝重放的记录，因此该限流器主要
	// 限制浪费解密 CPU 的暴力握手尝试。取值足够宽松，
	// 不会影响共享（NAT）IP 后面的合法客户端。
	handshakeRate = 50.0

	// handshakeBurst 是令牌桶的初始容量（允许的突发大小）。
	handshakeBurst = 100

	// 当 map 增长到超过这么多不同的源 IP 时，ipCleanupThreshold 触发一次
	// 空闲条目清理。
	ipCleanupThreshold = 4096

	// ipCleanupInterval 是两次清理扫描之间的最小间隔，这样轮换源 IP 的
	// 僵尸网络无法让每个请求都付出 O(n) 扫描的代价。
	ipCleanupInterval = time.Minute

	// ipCleanupTTL 是空闲限流条目在被删除前可以保留的时长。空闲这么久之后
	// 令牌桶必然已重新装满，因此删除并重建不会丢失任何状态。
	ipCleanupTTL = 30 * time.Minute

	// ipHardCap 是条目数量的绝对上限。源 IP 无限的僵尸网络不能无限制地
	// 撑大 map；即使在清理扫描之后仍达到上限，新的 IP 也会在不追踪的情况下
	// 被放行（fail open），从而合法用户永远不会被锁在门外，
	// 而已追踪的 IP 都受到各自令牌桶的限制。
	ipHardCap = 65536
)

// ipRateLimiter 使用每个 IP 一个令牌桶（golang.org/x/time/rate）来限制
// 每个源 IP 的握手尝试，缓解重放风暴和资源滥用。
type ipRateLimiter struct {
	mu          sync.Mutex
	entries     map[string]*ipRateEntry
	now         func() time.Time
	lastCleanup time.Time
	// lastCapWarn 对硬上限警告做限速。一旦 map 钉在 ipHardCap，
	// 每个未追踪的请求都会走那条分支，否则未经认证的轮换 IP 僵尸网络
	// 会把它变成日志洪水。
	lastCapWarn time.Time
}

type ipRateEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter() *ipRateLimiter {
	return &ipRateLimiter{entries: make(map[string]*ipRateEntry), now: time.Now}
}

// Allow 报告给定的 IP 当前是否可以进行一次握手。
func (l *ipRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if len(l.entries) >= ipCleanupThreshold && now.Sub(l.lastCleanup) >= ipCleanupInterval {
		l.cleanupLocked()
		l.lastCleanup = now
	}

	e, ok := l.entries[ip]
	if !ok {
		if len(l.entries) >= ipHardCap {
			// 再清理一次，以防时间间隔门控了上一次清理；
			// 如果 map 仍然已满，则放行（fail open）而不是直接拒绝合法流量。
			l.cleanupLocked()
			l.lastCleanup = now
			if len(l.entries) >= ipHardCap {
				if now.Sub(l.lastCapWarn) >= ipCleanupInterval {
					l.lastCapWarn = now
					log.Warn("[RATELIMIT] entry hard cap reached, admitting untracked ip", "cap", ipHardCap)
				}
				return true
			}
		}
		e = &ipRateEntry{lim: rate.NewLimiter(rate.Limit(handshakeRate), handshakeBurst), lastSeen: now}
		l.entries[ip] = e
	}
	e.lastSeen = now
	return e.lim.AllowN(now, 1)
}

// cleanupLocked 删除空闲达到 ipCleanupTTL 的条目，防止 map 无界增长。
// 调用方必须持有 l.mu。
func (l *ipRateLimiter) cleanupLocked() {
	now := l.now()
	for ip, e := range l.entries {
		if now.Sub(e.lastSeen) > ipCleanupTTL {
			delete(l.entries, ip)
		}
	}
}
