package handler

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/stretchr/testify/require"
)

// primeTracked 让 Allow 建出条目并把正常桶补满：惩罚只作用于被追踪的 IP
// （Allow 在硬上限处 fail open 的 IP 根本没有条目，见 Penalize）。
func primeTracked(t *testing.T, l *ipRateLimiter, now *time.Time, ip string) {
	t.Helper()
	if !l.Allow(ip) {
		t.Fatalf("priming allow for %s was rejected", ip)
	}
	*now = now.Add(time.Second)
}

// TestIPRateLimiter_PenaltyThrottles 固定惩罚期的速率：连续解密失败到阈值后，该 IP
// 只剩 penaltyBurst 次突发和每秒 penaltyRate 次补充。
func TestIPRateLimiter_PenaltyThrottles(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }
	primeTracked(t, l, &now, "1.2.3.4")

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
	for i := range int(penaltyRate) {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("token %d should refill at penaltyRate", i)
		}
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
	primeTracked(t, l, &now, "1.2.3.4")

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
	primeTracked(t, l, &now, "1.2.3.4")

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
	primeTracked(t, l, &now, "1.2.3.4")

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
	primeTracked(t, l, &now, "1.2.3.4")

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
	primeTracked(t, l, &now, "1.2.3.4")

	for range failureThreshold {
		l.Penalize("1.2.3.4")
	}
	for i := range handshakeBurst {
		if !l.Allow("5.6.7.8") {
			t.Fatalf("request %d from another ip should be allowed", i)
		}
	}
}

// TestIPRateLimiter_SuccessResetsFailures 固定成功握手清零失败计数：阈值是"连续失败"
// 而不是累计，否则横跨数天的三次失败会在最后一次触发惩罚。
func TestIPRateLimiter_SuccessResetsFailures(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }
	primeTracked(t, l, &now, "1.2.3.4")

	for range failureThreshold - 1 {
		l.Penalize("1.2.3.4")
	}
	l.RecordSuccess("1.2.3.4")
	l.Penalize("1.2.3.4")

	allowed := 0
	for range handshakeBurst {
		if l.Allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed != handshakeBurst {
		t.Fatalf("allowed = %d, want %d: failures before a successful handshake must not accumulate",
			allowed, handshakeBurst)
	}
}

// TestIPRateLimiter_PenalizeRespectsHardCap 固定惩罚不能绕过 ipHardCap：Allow 在硬
// 上限处故意 fail open 不建条目，Penalize 若补建就把上限变成摆设。
func TestIPRateLimiter_PenalizeRespectsHardCap(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }
	// 直接铺满条目，避免 65536 次令牌桶分配。
	for i := range ipHardCap {
		l.entries[fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)] = &ipRateEntry{lastSeen: now}
	}
	l.lastCapWarn = now

	if !l.Allow("203.0.113.9") {
		t.Fatal("an untracked ip at the hard cap must be admitted (fail open)")
	}
	l.Penalize("203.0.113.9")
	if got := len(l.entries); got != ipHardCap {
		t.Fatalf("entries = %d, want %d: the penalty must not bypass the hard cap", got, ipHardCap)
	}
}

// TestDefaultPenaltyEligible 固定来源判定：回环、私网与 CGNAT 后面整片用户共用一个
// 源 IP（同机反代/局域网/运营商 NAT），按 IP 惩罚会放大成整站降速。
func TestDefaultPenaltyEligible(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"192.168.1.10", false},
		{"172.16.0.1", false},
		{"100.64.1.2", false}, // CGNAT
		{"::1", false},
		{"fe80::1%en0", false}, // 链路本地带 zone
		{"fd00::1", false},
		{"0.0.0.0", false},
		{"8.8.8.8", true},
		{"2606:4700::1111", true},
		{"not-an-ip", false},
	}
	for _, tt := range tests {
		if got := defaultPenaltyEligible(tt.ip); got != tt.want {
			t.Errorf("defaultPenaltyEligible(%q) = %v, want %v", tt.ip, got, tt.want)
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

func alwaysEligible(string) bool { return true }

// newPenaltyTestHandler 用注入的来源判定覆盖惩罚路径：httptest 的请求来自回环，
// 默认判定（defaultPenaltyEligible）会把它当作共享源地址排除掉。
func newPenaltyTestHandler(penaltyEligible func(string) bool, disableFailurePenalty bool) *ProxyHandler {
	return newProxyHandlerWithDeps(ProxyHandlerConfig{
		MasterKey:             bytes.Repeat([]byte{0x42}, 32),
		AllowedMethods:        []string{protocol.MethodAES256GCM.String()},
		Timeouts:              config.NewTimeouts(5 * time.Second),
		HandshakeTimeout:      time.Second,
		Shaper:                shaper.Config{BatchWindowMS: 1},
		PenaltyEligible:       penaltyEligible,
		DisableFailurePenalty: disableFailurePenalty,
	}, newStubbedDeps())
}

// TestServeHTTP_DecryptFailuresPenalizeIP 固定从握手失败到惩罚的接线：只有解密失败
// 才计数，且响应仍与普通网站一致。
func TestServeHTTP_DecryptFailuresPenalizeIP(t *testing.T) {
	h := newPenaltyTestHandler(alwaysEligible, false)
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
	h := newPenaltyTestHandler(alwaysEligible, false)
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

// TestServeHTTP_SharedSourceIsNotPenalized 固定默认行为：回环来源（同机反向代理）
// 的失败不降速，否则任何能触达入口的人都能把整片用户打到惩罚档。
func TestServeHTTP_SharedSourceIsNotPenalized(t *testing.T) {
	h := newPenaltyTestHandler(nil, false) // nil 走 defaultPenaltyEligible
	srv := newRejectTestServer(t, h)
	tr := newRejectTestClient(t)

	for range failureThreshold {
		salt, err := crypto.GenerateSalt()
		require.NoError(t, err)
		postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltToB64(salt), bytes.NewReader(badCipherRecord(64)))
	}

	h.ipLimiter.mu.Lock()
	e := h.ipLimiter.entries["127.0.0.1"]
	penalized := e != nil && !e.penaltyUntil.IsZero()
	h.ipLimiter.mu.Unlock()
	require.False(t, penalized, "loopback sources must never be penalized")
}

// TestServeHTTP_DisableFailurePenalty 固定开关：CDN 回源等共用公网源地址的部署可以
// 整体关掉降速。
func TestServeHTTP_DisableFailurePenalty(t *testing.T) {
	h := newPenaltyTestHandler(alwaysEligible, true)
	srv := newRejectTestServer(t, h)
	tr := newRejectTestClient(t)

	for range failureThreshold {
		salt, err := crypto.GenerateSalt()
		require.NoError(t, err)
		postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltToB64(salt), bytes.NewReader(badCipherRecord(64)))
	}

	h.ipLimiter.mu.Lock()
	e := h.ipLimiter.entries["127.0.0.1"]
	penalized := e != nil && !e.penaltyUntil.IsZero()
	h.ipLimiter.mu.Unlock()
	require.False(t, penalized, "disable_failure_penalty must turn the penalty off")
}

// TestIPRateLimiter_PenalizeReportsEntry 固定 entered 只在连续失败跨过阈值的那一次
// 为真：调用方据此打"进入惩罚期"告警，而不是每次失败都打一遍。
func TestIPRateLimiter_PenalizeReportsEntry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter()
	l.now = func() time.Time { return now }
	primeTracked(t, l, &now, "1.2.3.4")

	for i := 1; i < failureThreshold; i++ {
		if l.Penalize("1.2.3.4") {
			t.Fatalf("failure %d reported entry before the threshold", i)
		}
	}
	if !l.Penalize("1.2.3.4") {
		t.Fatal("the threshold failure must report entry")
	}
	if l.Penalize("1.2.3.4") {
		t.Fatal("another failure inside the penalty window must only renew it")
	}

	// 成功握手清零失败计数后，下一次跨阈值是一次新的进入。
	l.RecordSuccess("1.2.3.4")
	for range failureThreshold - 1 {
		l.Penalize("1.2.3.4")
	}
	if !l.Penalize("1.2.3.4") {
		t.Fatal("crossing the threshold again after a success must report entry")
	}
}

// 全局 logger 是进程级状态，本用例不能并行。
func TestLogPenaltyEnteredRateLimitsByWindow(t *testing.T) {
	rec := &recordingHandler{}
	prev := log.Logger()
	log.SetLogger(slog.New(rec))
	t.Cleanup(func() { log.SetLogger(prev) })

	h := &ProxyHandler{}
	for range 3 {
		h.logPenaltyEntered("1.2.3.4", config.EndpointTCP)
	}
	if got := len(rec.at(slog.LevelWarn)); got != 1 {
		t.Fatalf("got %d Warn records in the window, want 1", got)
	}
	if h.suppressedPenalties != 2 {
		t.Fatalf("suppressedPenalties = %d, want 2", h.suppressedPenalties)
	}

	// 把上次告警时间推到窗口之前：下一条必须带出被折叠的源数量。
	h.penaltyWarnMu.Lock()
	h.lastPenaltyWarn = time.Now().Add(-2 * penaltyWarnInterval)
	h.penaltyWarnMu.Unlock()
	h.logPenaltyEntered("5.6.7.8", config.EndpointTCP)

	warns := rec.at(slog.LevelWarn)
	require.Len(t, warns, 2)
	if got := attrsOf(warns[1])["suppressed"]; got != "2" {
		t.Fatalf("suppressed = %q, want 2", got)
	}
}
