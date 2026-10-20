package handler

import (
	"sync"
	"time"

	"github.com/nange/easyss/v3/log"
	"golang.org/x/time/rate"
)

const (
	// handshakeRate 是每个源 IP 每秒的握手数。salt 重放缓存已在拨号前拒掉重放，
	// 这里主要限制白耗解密 CPU 的暴力握手；取值宽松到不影响 NAT 后面的合法客户端。
	handshakeRate = 50.0

	// handshakeBurst 是令牌桶的初始容量（允许的突发大小）。
	handshakeBurst = 100

	// map 增长到这么多源 IP 时触发一次空闲条目清理。
	ipCleanupThreshold = 4096

	// 两次清理扫描的最小间隔，否则轮换源 IP 的僵尸网络能让每个请求都付一次 O(n) 扫描。
	ipCleanupInterval = time.Minute

	// ipCleanupTTL 是空闲条目的保留时长。空闲这么久后令牌桶必然已装满，删除不会丢状态。
	ipCleanupTTL = 30 * time.Minute

	// ipHardCap 是条目数的绝对上限。清理后仍满则放行新 IP 而不追踪（fail open），
	// 合法用户不会被锁在门外，已追踪的 IP 仍受各自令牌桶限制。
	ipHardCap = 65536
)

// ipRateLimiter 每个源 IP 一个令牌桶，限制握手尝试以缓解重放风暴与资源滥用。
type ipRateLimiter struct {
	mu          sync.Mutex
	entries     map[string]*ipRateEntry
	now         func() time.Time
	lastCleanup time.Time
	// lastCapWarn 给硬上限警告限速。map 钉在 ipHardCap 后每个未追踪请求都走那条分支，
	// 否则轮换 IP 的僵尸网络会把它变成日志洪水。
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
			// 再清理一次，时间间隔可能门控了上一次清理；仍然满则放行（fail open）
			// 而不是拒绝合法流量。
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

// cleanupLocked 删除空闲达到 ipCleanupTTL 的条目，防止 map 无界增长。调用方必须持有 l.mu。
func (l *ipRateLimiter) cleanupLocked() {
	now := l.now()
	for ip, e := range l.entries {
		if now.Sub(e.lastSeen) > ipCleanupTTL {
			delete(l.entries, ip)
		}
	}
}
