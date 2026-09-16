package handler

import (
	"encoding/base64"
	"math/rand"
	"testing"
	"time"
)

func TestSaltCache_MarkSeen(t *testing.T) {
	c := newSaltCache()

	salt := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	const endpoint = "/v3/tcp"

	if c.MarkSeen(endpoint, salt) {
		t.Fatal("first MarkSeen should report not-seen")
	}
	if !c.MarkSeen(endpoint, salt) {
		t.Fatal("second MarkSeen of the same salt should report seen (replay)")
	}

	// 同一 salt 出现在不同端点上时不能视为重放：
	// 按端点区分的 AAD 使该记录无法解密，而烧掉该条目会让攻击者逐出另一端点的防护。
	if c.MarkSeen("/v3/udp", salt) {
		t.Fatal("the same salt on a different endpoint should report not-seen")
	}

	other := base64.RawURLEncoding.EncodeToString(append([]byte(nil), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))
	if c.MarkSeen(endpoint, other) {
		t.Fatal("a different salt should report not-seen")
	}
}

func TestSaltCache_DistinctSalts(t *testing.T) {
	c := newSaltCache()
	rng := rand.New(rand.NewSource(42))
	for range 1000 {
		buf := make([]byte, 16)
		_, _ = rng.Read(buf)
		salt := base64.RawURLEncoding.EncodeToString(buf)
		if c.MarkSeen("/v3/tcp", salt) {
			t.Fatalf("salt %q reported as seen on first use", salt)
		}
	}
}

// TestSaltCache_ConcurrentMarkSeen 验证 check-and-set 的原子性：
// 携带同一 salt 的并发请求必须恰好观察到一次 not-seen 结果
// （针对 Get/Set TOCTOU 的回归测试）。
func TestSaltCache_ConcurrentMarkSeen(t *testing.T) {
	c := newSaltCache()
	salt := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	const goroutines = 32

	start := make(chan struct{})
	results := make(chan bool, goroutines)
	for range goroutines {
		go func() {
			<-start
			results <- c.MarkSeen("/v3/tcp", salt)
		}()
	}
	close(start)

	seen := 0
	for range goroutines {
		if <-results {
			seen++
		}
	}
	if seen != goroutines-1 {
		t.Fatalf("seen = %d, want %d (exactly one not-seen result)", seen, goroutines-1)
	}
}

func TestIPRateLimiter_BurstThenReject(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }

	for i := range handshakeBurst {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d within burst should be allowed", i)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("request beyond burst should be rejected")
	}
}

func TestIPRateLimiter_Refill(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }

	for range handshakeBurst {
		l.Allow("1.2.3.4")
	}

	// 前进 1 秒：恰好补充 handshakeRate 个令牌。
	now = now.Add(time.Second)
	allowed := 0
	for range int(handshakeRate) {
		if l.Allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed != int(handshakeRate) {
		t.Fatalf("allowed = %d, want %d", allowed, int(handshakeRate))
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("request after consuming refilled tokens should be rejected")
	}
}

func TestIPRateLimiter_PerIPIsolation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }

	for range handshakeBurst {
		l.Allow("1.2.3.4")
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("exhausted IP should be rejected")
	}
	if !l.Allow("5.6.7.8") {
		t.Fatal("a fresh IP should be allowed independently")
	}
}
