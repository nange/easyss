package http2

import (
	"context"
	"crypto/tls"
	"math"
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

const testProbePayloadSize = 64 * 1024

// newProbeServer 启动一个提供探测端点的真实 TLS 服务器，载荷长度由调用方指定。
func newProbeServer(t *testing.T, payloadSize int) (*httptest.Server, string) {
	t.Helper()
	masterKey, err := crypto.DeriveMasterKey("test-password")
	if err != nil {
		t.Fatal(err)
	}
	token, err := crypto.ProbeToken(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, payloadSize)
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
	ts, token := newProbeServer(t, testProbePayloadSize)
	prober := &slotProber{serverURL: ts.URL, token: token}

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

// 载荷长度是服务端侧的可调参数：客户端接受服务端声明的任意可测长度，否则调整
// ProbePayloadSize 会让旧客户端把探测判成 unsupported 并永久退回被动检测。
func TestSlotProberAcceptsAnyServerPayloadSize(t *testing.T) {
	for _, size := range []int{probeMinBodySize, config.ProbePayloadSize, 512 * 1024} {
		ts, token := newProbeServer(t, size)
		prober := &slotProber{serverURL: ts.URL, token: token}

		if _, verdict := prober.probe(context.Background(), newProbeSlot()); verdict != probeFast {
			t.Fatalf("payload size %d: verdict = %v, want probeFast", size, verdict)
		}
	}
}

// 首块在计时起点之前到达，不能计入分子：否则 128KB 载荷的速率会被抬高到 4/3，
// 名义 80KB/s 实际只判到 60KB/s。
func TestProbeSpeed(t *testing.T) {
	const kib = 1024
	cases := []struct {
		name    string
		total   int64
		first   int64
		elapsed time.Duration
		want    float64
	}{
		{"first chunk excluded", 128 * kib, 32 * kib, 1200 * time.Millisecond, 80 * kib},
		{"first chunk excluded can cross the threshold", 128 * kib, 32 * kib, 2400 * time.Millisecond, 40 * kib},
		{"whole payload timed", 128 * kib, 0, 1600 * time.Millisecond, 80 * kib},
		{"nothing delivered", 0, 0, time.Second, 0},
		{"no measurable window", 128 * kib, 128 * kib, 0, maxProbeSpeed},
		{"clamped to the cap", 128 * kib, 32 * kib, time.Microsecond, maxProbeSpeed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := probeSpeed(tc.total, tc.first, tc.elapsed)
			if math.Abs(got-tc.want) > 1 {
				t.Fatalf("probeSpeed(%d, %d, %v) = %v, want %v",
					tc.total, tc.first, tc.elapsed, got, tc.want)
			}
		})
	}
}

// 长度不可测只说明这次拿不到可测载荷，不能像"端点不存在"那样永久关掉主动探测：
// 流式响应（无 Content-Length）与窗口外尺寸都必须只退避。
func TestSlotProberInconclusiveOnUnmeasurableLength(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"streamed without content length", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_ = http.NewResponseController(w).Flush()
		}},
		{"below the measurable window", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(probeMinBodySize-1))
			w.WriteHeader(http.StatusOK)
		}},
		{"above the measurable window", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(probeMaxBodySize+1))
			w.WriteHeader(http.StatusOK)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(tc.handler)
			t.Cleanup(ts.Close)
			prober := &slotProber{serverURL: ts.URL, token: "unused"}

			if _, verdict := prober.probe(context.Background(), newProbeSlot()); verdict != probeInconclusive {
				t.Fatalf("verdict = %v, want probeInconclusive", verdict)
			}
		})
	}
}

func TestSlotProberSlowOnEmptyBody(t *testing.T) {
	// 探测超时内不投递任何内容的 200 octet-stream 响应计为慢速证据。
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(testProbePayloadSize))
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
	}))
	t.Cleanup(ts.Close)
	prober := &slotProber{serverURL: ts.URL, token: "unused"}

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
	prober := &slotProber{serverURL: ts.URL, token: "unused"}

	speed, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeSlow {
		t.Fatalf("verdict = %v (speed %v), want probeSlow for a truncated payload", verdict, speed)
	}
}

// 探测自身超时不是"慢"的证据：超时只说明预算用完，不代表服务端截断了载荷。先跑一次完整
// 探测预热连接，让调用方的截止时间只覆盖载荷读取（拨号 + TLS + h2 握手在高负载 CI 上可能
// 超过这个预算）。
func TestSlotProberTimeoutUsesDeliveredRate(t *testing.T) {
	const payloadSize = 256 * 1024
	var requests atomic.Int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(payloadSize))
		w.WriteHeader(http.StatusOK)
		if requests.Add(1) == 1 {
			_, _ = w.Write(make([]byte, payloadSize)) // 预热请求：送完整载荷
			return
		}
		_, _ = w.Write(make([]byte, payloadSize*3/4)) // 送出 192KB 后保持流打开
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	prober := &slotProber{serverURL: ts.URL, token: "unused"}
	slot := newProbeSlot()

	if _, verdict := prober.probe(context.Background(), slot); verdict != probeFast {
		t.Fatalf("warm-up verdict = %v, want probeFast", verdict)
	}

	// 调用方的截止时间比 ProbeTimeout 早：载荷送不完是预算不足，不是服务端截断。
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	speed, verdict := prober.probe(ctx, slot)

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
	prober := &slotProber{serverURL: ts.URL, token: "unused"}

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
	prober := &slotProber{serverURL: ts.URL, token: "unused"}

	_, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeInconclusive {
		t.Fatalf("verdict = %v, want probeInconclusive", verdict)
	}
}

func TestSlotProberInconclusiveOnDialError(t *testing.T) {
	ts, _ := newProbeServer(t, testProbePayloadSize)
	deadURL := ts.URL
	ts.Close() // 从此连接被拒绝

	prober := &slotProber{serverURL: deadURL, token: "unused"}

	_, verdict := prober.probe(context.Background(), newProbeSlot())

	if verdict != probeInconclusive {
		t.Fatalf("verdict = %v, want probeInconclusive", verdict)
	}
}

// TestSlotProberWithoutConnectionCannotJudge 是 alive 那条不变量的另一半：这一代没有连接时
// 吞吐探测同样不得白拨一条，否则结论属于另一条连接。
func TestSlotProberWithoutConnectionCannotJudge(t *testing.T) {
	ts, token := newProbeServer(t, testProbePayloadSize)
	prober := &slotProber{serverURL: ts.URL, token: token}

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
	ts, token := newProbeServer(t, testProbePayloadSize)
	prober := &slotProber{serverURL: ts.URL, token: token}

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

// 判活只能相信被探测的那条连接：这一代的连接已不可用时，net/http 会让同一张池再拨一条
// （ErrNoCachedConn 路径，MaxConnsPerHost=1 挡不住），HEAD 由新连接应答时必须报"不通"。
func TestSlotProberAliveRejectsResponseFromAnotherConnection(t *testing.T) {
	ts, token := newProbeServer(t, testProbePayloadSize)
	prober := &slotProber{serverURL: ts.URL, token: token}

	var dials atomic.Int32
	gen := &slotTransport{}
	gen.tr = &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 测试服务器证书
		ForceAttemptHTTP2: true,
		MaxConnsPerHost:   1,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err == nil {
				// 生产里 DialTLSContext 会登记新连接的身份：这里模拟同一代被换上了另一条连接。
				gen.conn.Store(&slotConn{c: c})
			}
			return c, err
		},
	}
	gen.conn.Store(&slotConn{c: &countingConn{}})

	alive, ok := prober.alive(context.Background(), gen)
	if !ok || alive {
		t.Fatalf("alive = (%v, %v), want (false, true) when another connection answered", alive, ok)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1", got)
	}
}
