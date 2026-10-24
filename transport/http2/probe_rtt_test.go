package http2

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/server/handler"
	"github.com/nange/easyss/v3/stats"
)

// TestProbeRTTCountsRequestToFirstBodyByte 守住 probe 的计时基准：样本必须从发起请求算
// 到首个响应体分块。h2 客户端的 RoundTrip 只等响应头而读循环并发跑，大 RTT 链路上载荷
// 常在 RoundTrip 返回前就缓冲进本流管道，基准取错时量到的只是清缓冲区的微秒级耗时。
// 服务端在写出任何字节（含响应头）前先停 serverDelay，故判据不依赖客户端调度时序。
func TestProbeRTTCountsRequestToFirstBodyByte(t *testing.T) {
	// 只需远大于取走已缓冲载荷的微秒级耗时；正确样本由 time.Sleep 保证不小于它。
	const serverDelay = 100 * time.Millisecond

	masterKey, err := crypto.DeriveMasterKey("test-password")
	if err != nil {
		t.Fatal(err)
	}
	token, err := crypto.ProbeToken(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	ph, err := handler.NewProbeHandler(masterKey, make([]byte, testProbePayloadSize), nil)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/v3/probe", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RoundTrip 在延迟结束后才返回，所以这段延迟只能被"请求发出之前"的基准覆盖。
		time.Sleep(serverDelay)
		ph.ServeHTTP(w, r)
	}))
	ts := httptest.NewUnstartedServer(mux)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)

	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 测试服务器自签证书
		ForceAttemptHTTP2: true,
		MaxConnsPerHost:   1,
	}
	t.Cleanup(tr.CloseIdleConnections)
	slot := probeSlotWithPool(tr)

	stats.ResetCounters()
	prober := &slotProber{serverURL: ts.URL, token: token, payloadSize: testProbePayloadSize}
	speed, verdict := prober.probe(t.Context(), slot)
	if verdict != probeFast {
		t.Fatalf("verdict = %v, want probeFast (speed=%v)", verdict, speed)
	}
	snap := stats.Collect()
	got := snap.AvgRTT()

	t.Logf("recordedRTT=%v rttCount=%d", got.Round(time.Microsecond), snap.RTTCount)

	// 服务端写出首个字节前至少停了 serverDelay，正确的样本不可能短于它。
	if got < serverDelay {
		t.Fatalf("recorded RTT = %v, want >= server delay %v: sample only measured buffer drain, not request-to-first-byte",
			got, serverDelay)
	}
}
