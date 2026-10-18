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

// TestProbeRTTCountsRequestToFirstBodyByte 保护 probe 的路径 RTT 计时基准：
// 样本必须覆盖"发起请求 -> 首个响应体分块"，而不是"RoundTrip 返回 -> 首个
// 分块"。
//
// 缺陷成因（真实链路上以微秒级样本暴露）：Go 的 HTTP/2 客户端在独立
// goroutine 里写请求体，RoundTrip 只等响应头；而连接上的读循环是并发跑的。
// 大 RTT 链路上响应头与首批载荷几乎同时到达，读循环可在 RoundTrip 返回之前
// 就把载荷缓冲进本流管道。此时若把计时基准取在 RoundTrip 之后，量到的就只是
// "从缓冲区取走第一个分块"的耗时，真实路径 RTT 会被整段丢掉。
//
// 判据不依赖客户端调度时序：测试服务器收到 probe 后先停 serverDelay 再写出
// 任何响应字节（含响应头），因此"发起请求 -> 首个响应体分块"必然不小于这个
// 延迟；而"RoundTrip 返回 -> 首个分块"几乎为 0（响应头与载荷几乎同时到达，
// 载荷通常已被读循环缓冲进本流管道）。基准取错时样本会明显短于延迟，
// 无论客户端在发起请求或读响应时被调度器推迟多久都不会误报。
func TestProbeRTTCountsRequestToFirstBodyByte(t *testing.T) {
	// 只需远大于"响应头之后取走已缓冲载荷"的耗时（缺陷实现的样本，实测
	// 微秒级）即可；正确实现的样本由 time.Sleep 保证不小于它，因此调小
	// 不会引入误报，只影响回归被发现的余量。
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
		// 在写出任何响应字节（包括响应头）之前停住：RoundTrip 只有在延迟
		// 结束后才会返回，所以这段延迟只能被"请求发出之前"的基准覆盖。
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
	slot := slotWithPool(tr)

	stats.ResetCounters()
	prober := &slotProber{serverURL: ts.URL, token: token, payloadSize: testProbePayloadSize}
	speed, verdict := prober.probe(t.Context(), slot)
	if verdict != probeFast {
		t.Fatalf("verdict = %v, want probeFast (speed=%v)", verdict, speed)
	}
	snap := stats.Collect()
	got := snap.AvgRTT()

	t.Logf("recordedRTT=%v rttCount=%d", got.Round(time.Microsecond), snap.RTTCount)

	// 服务端在写出首个字节之前至少停了 serverDelay，因此正确的样本不可能
	// 短于它；基准取错时样本只包含缓冲区取数（微秒级）。
	if got < serverDelay {
		t.Fatalf("recorded RTT = %v, want >= server delay %v: sample only measured buffer drain, not request-to-first-byte",
			got, serverDelay)
	}
}
