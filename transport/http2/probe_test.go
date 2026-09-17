package http2

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/server/handler"
	"github.com/nange/easyss/v3/stats"
)

const testProbePayloadSize = 4096

// newProbeServer 启动一个提供探测端点的真实 TLS 服务器。
func newProbeServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	masterKey, err := crypto.DeriveMasterKey("test-password")
	if err != nil {
		t.Fatal(err)
	}
	token, err := crypto.ProbeToken(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, testProbePayloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	// 这里的探针测试只覆盖成功路径，回退页面由 nil（内置实例）承担。
	h, err := handler.NewProbeHandler(masterKey, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, token
}

// newProbeSlot 构建一个槽位，其 transport 用普通 TLS 与测试服务器通信
// （生产 transport 使用 uTLS，此处无关紧要）。
func newProbeSlot() *transportSlot {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 测试服务器证书
		ForceAttemptHTTP2: true,
		MaxConnsPerHost:   1,
	}
	return &transportSlot{t: tr}
}

func TestSlotProberFast(t *testing.T) {
	ts, token := newProbeServer(t)
	prober := &slotProber{serverURL: ts.URL, token: token, payloadSize: testProbePayloadSize}

	stats.ResetCounters()
	speed, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeFast {
		t.Fatalf("verdict = %v, want probeFast (speed %v)", verdict, speed)
	}
	if speed < float64(sharedconfig.DegradedThroughputThreshold) {
		t.Fatalf("speed %v below the degraded threshold", speed)
	}
	// 成功的探测必须贡献一个纯路径 RTT 样本（响应头到达 ->
	// 首个响应体块），与按请求采样的口径一致。
	if got := stats.Collect().RTTCount; got != 1 {
		t.Fatalf("RTTCount = %d, want 1 after a fast probe", got)
	}
}

func TestSlotProberSlowOnEmptyBody(t *testing.T) {
	// 探测超时内不投递任何内容的 200 octet-stream 响应计为慢速证据。
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
	}))
	t.Cleanup(ts.Close)
	prober := &slotProber{serverURL: ts.URL, token: "unused", payloadSize: testProbePayloadSize}

	speed, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeSlow {
		t.Fatalf("verdict = %v, want probeSlow (speed %v)", verdict, speed)
	}
	if speed != 0 {
		t.Fatalf("speed = %v, want 0", speed)
	}
}

func TestSlotProberUnsupportedOnHTML(t *testing.T) {
	// 不是探测载荷的 200 页面（例如旧服务器的 fallback HTML）
	// 把探测标记为 unsupported。
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>fallback</body></html>"))
	}))
	t.Cleanup(ts.Close)
	prober := &slotProber{serverURL: ts.URL, token: "unused", payloadSize: testProbePayloadSize}

	_, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeUnsupported {
		t.Fatalf("verdict = %v, want probeUnsupported", verdict)
	}
}

func TestSlotProberInconclusiveOnErrorStatus(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	t.Cleanup(ts.Close)
	prober := &slotProber{serverURL: ts.URL, token: "unused", payloadSize: testProbePayloadSize}

	_, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeInconclusive {
		t.Fatalf("verdict = %v, want probeInconclusive", verdict)
	}
}

func TestSlotProberInconclusiveOnDialError(t *testing.T) {
	ts, _ := newProbeServer(t)
	deadURL := ts.URL
	ts.Close() // 从此连接被拒绝

	prober := &slotProber{serverURL: deadURL, token: "unused", payloadSize: testProbePayloadSize}

	_, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeInconclusive {
		t.Fatalf("verdict = %v, want probeInconclusive", verdict)
	}
}
