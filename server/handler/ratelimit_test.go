package handler

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/stretchr/testify/require"
)

// TestIPRateLimiter_PenaltyThrottles 固定惩罚期的速率：连续解密失败到阈值后，该 IP
// 只剩 penaltyBurst 次突发和每秒一次补充。
func TestIPRateLimiter_PenaltyThrottles(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }

	for range failureThreshold {
		l.Penalize("1.2.3.4")
	}

	allowed := 0
	for range penaltyBurst + 3 {
		if l.Allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed != penaltyBurst {
		t.Fatalf("allowed = %d, want %d (penalty burst)", allowed, penaltyBurst)
	}

	now = now.Add(time.Second)
	if !l.Allow("1.2.3.4") {
		t.Fatal("penalty bucket should refill one token per second")
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("penalty bucket must refill at penaltyRate, not at handshakeRate")
	}
}

// TestIPRateLimiter_BelowThresholdKeepsNormalRate 固定"单次瞬断不降速"：少于阈值次
// 失败仍走正常令牌桶，客户端一次请求的重试风暴不会把自己降速。
func TestIPRateLimiter_BelowThresholdKeepsNormalRate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }

	for range failureThreshold - 1 {
		l.Penalize("1.2.3.4")
	}
	for i := range handshakeBurst {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d within the normal burst should be allowed", i)
		}
	}
}

// TestIPRateLimiter_SuccessClearsPenalty 固定恢复路径：改对口令后的第一次成功握手
// 立即回到正常速率，不用等惩罚窗口走完。
func TestIPRateLimiter_SuccessClearsPenalty(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }

	for range failureThreshold {
		l.Penalize("1.2.3.4")
	}
	l.RecordSuccess("1.2.3.4")

	for i := range handshakeBurst {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d after a successful handshake should be allowed", i)
		}
	}
}

// TestIPRateLimiter_PenaltyExpires 固定窗口结束后的自动恢复：期间没有任何成功握手，
// 惩罚也必须自己过期。
func TestIPRateLimiter_PenaltyExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }

	for range failureThreshold {
		l.Penalize("1.2.3.4")
	}
	now = now.Add(penaltyWindow)

	for i := range handshakeBurst {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d after the penalty window should be allowed", i)
		}
	}
}

// TestIPRateLimiter_PenaltyExtendsOnFailure 固定"等待不能躲过惩罚"：窗口内的再次失败
// 会续期，而不是从第一次失败开始固定计时。
func TestIPRateLimiter_PenaltyExtendsOnFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }

	for range failureThreshold {
		l.Penalize("1.2.3.4")
	}
	now = now.Add(penaltyWindow / 2)
	l.Penalize("1.2.3.4")

	// 原来的窗口已到期，但惩罚被续期，仍然是降速桶。
	now = now.Add(penaltyWindow/2 + time.Second)
	allowed := 0
	for range penaltyBurst + 1 {
		if l.Allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed != penaltyBurst {
		t.Fatalf("allowed = %d, want %d: the penalty must be extended by later failures", allowed, penaltyBurst)
	}
}

// TestIPRateLimiter_PenaltyIsPerIP 固定惩罚只作用于出问题的那个源 IP。
func TestIPRateLimiter_PenaltyIsPerIP(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }

	for range failureThreshold {
		l.Penalize("1.2.3.4")
	}
	for i := range handshakeBurst {
		if !l.Allow("5.6.7.8") {
			t.Fatalf("request %d from another ip should be allowed", i)
		}
	}
}

// badCipherRecord 返回一条长度前缀合法、但无法通过认证的记录：服务端会走到 AEAD
// 失败，也就是"对端没有主密钥"。
func badCipherRecord(cipherLen int) []byte {
	b := make([]byte, protocol.MaxCipherLenSize+cipherLen)
	b[0], b[1], b[2] = byte(cipherLen>>16), byte(cipherLen>>8), byte(cipherLen)
	return b
}

func newPenaltyTestHandler() *ProxyHandler {
	return newProxyHandlerWithDeps(ProxyHandlerConfig{
		MasterKey:        bytes.Repeat([]byte{0x42}, 32),
		AllowedMethods:   []string{protocol.MethodAES256GCM.String()},
		Timeouts:         config.NewTimeouts(5 * time.Second),
		HandshakeTimeout: time.Second,
		Shaper:           shaper.Config{BatchWindowMS: 1},
	}, newStubbedDeps())
}

// TestServeHTTP_DecryptFailuresPenalizeIP 固定从握手失败到惩罚的接线：只有解密失败
// 才计数，且响应仍与普通网站一致。
func TestServeHTTP_DecryptFailuresPenalizeIP(t *testing.T) {
	h := newPenaltyTestHandler()
	srv := newRejectTestServer(t, h)
	tr := newRejectTestClient(t)

	for range failureThreshold {
		salt, err := crypto.GenerateSalt()
		require.NoError(t, err)
		resp, _ := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltToB64(salt),
			bytes.NewReader(badCipherRecord(64)))
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"a decrypt failure must stay indistinguishable from a normal site")
	}

	h.ipLimiter.mu.Lock()
	e, ok := h.ipLimiter.entries["127.0.0.1"]
	penalized := ok && !e.penaltyUntil.IsZero()
	h.ipLimiter.mu.Unlock()
	require.True(t, penalized, "repeated decrypt failures should penalize the source ip")
}

// TestServeHTTP_SuccessClearsPenalty 固定"改对口令马上能连"：惩罚期内的一次正确
// 握手必须放行（惩罚桶留了突发额度）并立即解除惩罚。
func TestServeHTTP_SuccessClearsPenalty(t *testing.T) {
	h := newPenaltyTestHandler()
	srv := newRejectTestServer(t, h)
	tr := newRejectTestClient(t)

	for range failureThreshold {
		salt, err := crypto.GenerateSalt()
		require.NoError(t, err)
		postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltToB64(salt), bytes.NewReader(badCipherRecord(64)))
	}

	saltB64, body := buildBootstrapRecord(t, bytes.Repeat([]byte{0x42}, 32), config.EndpointTCP,
		protocol.ProtoTCP, protocol.MethodAES256GCM, "example.com:443")
	resp, _ := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltB64, bytes.NewReader(body))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"),
		"a correct handshake must pass even while the ip is penalized")

	h.ipLimiter.mu.Lock()
	e := h.ipLimiter.entries["127.0.0.1"]
	cleared := e != nil && e.penaltyUntil.IsZero()
	h.ipLimiter.mu.Unlock()
	require.True(t, cleared, "a successful handshake must lift the penalty immediately")
}
