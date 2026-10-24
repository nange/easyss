package http2

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
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
	return probeSlotWithPool(tr)
}

func TestSlotProberFast(t *testing.T) {
	ts, token := newProbeServer(t)
	prober := &slotProber{serverURL: ts.URL, token: token, payloadSize: testProbePayloadSize}

	stats.ResetCounters()
	speed, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeFast {
		t.Fatalf("verdict = %v, want probeFast (speed %v)", verdict, speed)
	}
	if speed < float64(config.DegradedThroughputThreshold) {
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

// 服务端提前结束这条流（RST_STREAM）时，按已到达字节算出的吞吐不可比：最快的首块不能
// 当成整段载荷的速度。
func TestSlotProberTruncatedPayloadIsSlow(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(testProbePayloadSize))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, 1024)) // 只写出前 1KB，随后结束这条流
		_ = http.NewResponseController(w).Flush()
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	prober := &slotProber{serverURL: ts.URL, token: "unused", payloadSize: testProbePayloadSize}

	speed, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeSlow {
		t.Fatalf("verdict = %v (speed %v), want probeSlow for a truncated payload", verdict, speed)
	}
}

// 探测自身超时不是"慢"的证据：首字节慢导致载荷没读完时，按已到达字节算出的速度仍然有效。
func TestSlotProberTimeoutUsesDeliveredRate(t *testing.T) {
	const payloadSize = 64 * 1024
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(payloadSize))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, payloadSize*3/4)) // 先送 48KB，远高于降级阈值
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done() // 保持这条流打开，直到调用方的截止时间把探测打断
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	prober := &slotProber{serverURL: ts.URL, token: "unused", payloadSize: payloadSize}

	// 调用方的截止时间比 ProbeTimeout 早，用来触发"超时时载荷未送达完"。
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	speed, verdict := prober.probe(ctx, newProbeSlot())

	if verdict != probeFast {
		t.Fatalf("verdict = %v (speed %v), want probeFast: a deadline is not a slow verdict", verdict, speed)
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

// TestSlotProberWithoutConnectionCannotJudge 是 alive 那条不变量的另一半：这一代没有连接时
// 吞吐探测同样不得白拨一条，否则结论属于另一条连接。
func TestSlotProberWithoutConnectionCannotJudge(t *testing.T) {
	ts, token := newProbeServer(t)
	prober := &slotProber{serverURL: ts.URL, token: token, payloadSize: testProbePayloadSize}

	var dials atomic.Int32
	s := slotWithPool(&http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 测试服务器证书
		ForceAttemptHTTP2: true,
		MaxConnsPerHost:   1,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	})
	// gen.conn 保持为空：这一代的连接已经不在了。

	if _, verdict := prober.probe(context.Background(), s); verdict != probeInconclusive {
		t.Fatalf("verdict = %v, want probeInconclusive without a connection", verdict)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("dials = %d, want 0: a generation without a connection must not be dialed", got)
	}
}

// TestSlotProberAliveWithoutConnectionCannotJudge 固定"没有可探测的连接"的语义：
// 一代的连接已被关闭或回收时必须报"无法判定"，不能白拨一条新连接——那会给出
// 关于另一条连接的 alive 结论，还会在无人引用的池里滞留到空闲超时。
func TestSlotProberAliveWithoutConnectionCannotJudge(t *testing.T) {
	ts, token := newProbeServer(t)
	prober := &slotProber{serverURL: ts.URL, token: token, payloadSize: testProbePayloadSize}

	var dials atomic.Int32
	gen := &slotTransport{tr: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 测试服务器证书
		ForceAttemptHTTP2: true,
		MaxConnsPerHost:   1,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	// gen.conn 保持为空：这一代的连接已经不在了。

	alive, ok := prober.alive(context.Background(), gen)
	if ok || alive {
		t.Fatalf("alive = (%v, %v), want (false, false) without a connection", alive, ok)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("dials = %d, want 0: a generation without a connection must not be dialed", got)
	}

	// 连一代都没有时同理，且不得 panic。
	if alive, ok := prober.alive(context.Background(), nil); ok || alive {
		t.Fatalf("alive = (%v, %v), want (false, false) without a generation", alive, ok)
	}
}
