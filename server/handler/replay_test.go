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

	if c.MarkSeen(salt) {
		t.Fatal("first MarkSeen should report not-seen")
	}
	if !c.MarkSeen(salt) {
		t.Fatal("second MarkSeen of the same salt should report seen (replay)")
	}

	other := base64.RawURLEncoding.EncodeToString(append([]byte(nil), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))
	if c.MarkSeen(other) {
		t.Fatal("a different salt should report not-seen")
	}
}

func TestSaltCache_DistinctSalts(t *testing.T) {
	c := newSaltCache()
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 1000; i++ {
		buf := make([]byte, 16)
		_, _ = rng.Read(buf)
		salt := base64.RawURLEncoding.EncodeToString(buf)
		if c.MarkSeen(salt) {
			t.Fatalf("salt %q reported as seen on first use", salt)
		}
	}
}

func TestIPRateLimiter_BurstThenReject(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }

	for i := 0; i < handshakeBurst; i++ {
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

	for i := 0; i < handshakeBurst; i++ {
		l.Allow("1.2.3.4")
	}

	// Advance 1s: exactly handshakeRate tokens are replenished.
	now = now.Add(time.Second)
	allowed := 0
	for i := 0; i < int(handshakeRate); i++ {
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

	for i := 0; i < handshakeBurst; i++ {
		l.Allow("1.2.3.4")
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("exhausted IP should be rejected")
	}
	if !l.Allow("5.6.7.8") {
		t.Fatal("a fresh IP should be allowed independently")
	}
}
