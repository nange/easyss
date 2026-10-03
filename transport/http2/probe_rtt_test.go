package http2

import (
	"context"
	"crypto/tls"
	"io"
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
// "从缓冲区取走第一个分块"的耗时，真实路径 RTT 被整段丢掉。
//
// 本测试让 probe 请求排在一条正在写入的流之后（MaxConnsPerHost=1），使样本
// 至少包含"请求真正到达服务端"的等待时间；基准取错时这段等待会从样本里消失。
// 注意：单机回环的 RTT 只有微秒级，无法凭它稳定复现缓冲时序，缺陷本身是在
// 真实长链路上被观测并修复的（修复前 probe 样本 36µs~811µs，修复后 ≈207ms）。
func TestProbeRTTCountsRequestToFirstBodyByte(t *testing.T) {
	const probeAfter = 500 * time.Millisecond // 请求体仍在写入时发起 probe

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

	probeRecv := make(chan time.Time, 1)
	mux := http.NewServeMux()
	mux.Handle("/v3/probe", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case probeRecv <- time.Now():
		default:
		}
		ph.ServeHTTP(w, r)
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	mux.Handle("/v3/tcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, 1024))
		_, _ = io.Copy(io.Discard, r.Body)
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
	slot := &transportSlot{t: tr}

	// 用超大请求体占住这条连接：写入阻塞在流控窗口上，probe 请求因此要排队。
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close(); tr.CloseIdleConnections() })
	uploadReq, err := http.NewRequest(http.MethodPost, ts.URL+"/v3/tcp", pr)
	if err != nil {
		t.Fatal(err)
	}
	uploadCtx, cancelUpload := context.WithCancel(context.Background())
	t.Cleanup(cancelUpload)
	uploadReq = uploadReq.WithContext(uploadCtx)
	uploadStarted := make(chan struct{})
	go func() {
		close(uploadStarted)
		resp, err := tr.RoundTrip(uploadReq)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-uploadStarted
	go func() {
		buf := make([]byte, 64*1024)
		for {
			if _, err := pw.Write(buf); err != nil {
				return
			}
		}
	}()
	time.Sleep(probeAfter)

	stats.ResetCounters()
	start := time.Now()
	prober := &slotProber{serverURL: ts.URL, token: token, payloadSize: testProbePayloadSize}
	speed, verdict := prober.probe(t.Context(), slot)
	elapsed := time.Since(start)
	if verdict != probeFast {
		t.Fatalf("verdict = %v, want probeFast (speed=%v)", verdict, speed)
	}
	recvAt, ok := <-probeRecv
	if !ok {
		t.Fatal("probe never reached the server")
	}
	arrivalCost := recvAt.Sub(start)
	got := stats.Collect().AvgRTT()

	t.Logf("recordedRTT=%v probeElapsed=%v requestArrivalCost=%v",
		got.Round(time.Microsecond), elapsed.Round(time.Millisecond), arrivalCost.Round(time.Millisecond))

	// 请求必须先发出去才可能收到载荷，因此样本不可能短于"请求到达服务端"的
	// 耗时。基准取错时这段耗时会被整段丢掉。
	if minWant := arrivalCost * 6 / 10; got < minWant {
		t.Fatalf("recorded RTT = %v, want >= %v: sample only measured buffer drain, not path RTT",
			got, minWant)
	}
}
