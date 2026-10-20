package http2

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

// slowRTTRecorder 捕获包级日志器的记录，用于断言慢路径 RTT 的可见性。
type slowRTTRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *slowRTTRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (h *slowRTTRecorder) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *slowRTTRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *slowRTTRecorder) WithGroup(string) slog.Handler      { return h }

// 两条日志的消息原文。它们是用户 grep 的契约（限流后仍然必须能按消息找到
// 慢样本，以及被压掉的那些），因此这里刻意用字面量断言。
const (
	msgSlowRTTSample  = "[TRANSPORT] slow path RTT sample"
	msgSlowRTTSummary = "[TRANSPORT] slow path RTT samples suppressed"
)

func (h *slowRTTRecorder) at(level slog.Level) []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []slog.Record
	for _, r := range h.records {
		if r.Level == level {
			out = append(out, r)
		}
	}
	return out
}

// withMessage 按消息原文过滤（保持插入顺序）。"sample" 是 "samples suppressed"
// 的前缀，因此区分两条日志必须用完全相等而不是包含。
func (h *slowRTTRecorder) withMessage(msg string) []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []slog.Record
	for _, r := range h.records {
		if r.Message == msg {
			out = append(out, r)
		}
	}
	return out
}

// waitForWarn 等待首条 Warn 记录（异步落定的样本由 RoundTrip 的 goroutine 记录）。
func (h *slowRTTRecorder) waitForWarn(timeout time.Duration) []slog.Record {
	deadline := time.Now().Add(timeout)
	for {
		if warns := h.at(slog.LevelWarn); len(warns) > 0 {
			return warns
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// captureSlowRTTLogs 把包级日志器换成记录器，并在用例结束时恢复。
// transport/http2 的用例不并行，因此这个替换是安全的。
func captureSlowRTTLogs(t *testing.T) *slowRTTRecorder {
	t.Helper()
	rec := &slowRTTRecorder{}
	prev := log.Logger()
	log.SetLogger(slog.New(rec))
	t.Cleanup(func() { log.SetLogger(prev) })
	return rec
}

func attrsOf(r slog.Record) map[string]string {
	attrs := map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	return attrs
}

// assertSlowRTTWarn 断言这条记录就是一条越界的路径 RTT 慢样本日志。
func assertSlowRTTWarn(t *testing.T, r slog.Record) map[string]string {
	t.Helper()
	if r.Message != msgSlowRTTSample {
		t.Fatalf("message = %q, want %q", r.Message, msgSlowRTTSample)
	}
	attrs := attrsOf(r)
	d, err := time.ParseDuration(attrs["rtt"])
	if err != nil {
		t.Fatalf("rtt = %q, want a parseable duration (err %v)", attrs["rtt"], err)
	}
	if d < sharedconfig.SlowRTTWarnThreshold {
		t.Fatalf("rtt = %v, want >= %v", d, sharedconfig.SlowRTTWarnThreshold)
	}
	return attrs
}

// loggedCount 读取限流器已逐条打印的样本数（持锁），用于断言"样本确实经过了
// 这个限流器"，而不只是断言日志文本。
func (l *slowRTTLogLimiter) loggedCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.logged
}

// submitSlowSamples 向限流器提交 n 条越界样本，target 形如 example-i.com:443。
func submitSlowSamples(lim *slowRTTLogLimiter, n int) {
	for i := range n {
		lim.log(600*time.Millisecond+time.Duration(i)*time.Millisecond, slowRTTSample{
			source:   slowRTTSourceStream,
			endpoint: sharedconfig.EndpointTCP,
			target:   "example-" + strconv.Itoa(i) + ".com:443",
			slot:     &transportSlot{idx: i},
		})
	}
}

// TestLogSlowPathRTTOnSlowStreamSample 验证越界的引导往返样本会连同请求身份
// （endpoint/target）与承载它的槽位一起记 Warn，且样本照常进入统计。
func TestLogSlowPathRTTOnSlowStreamSample(t *testing.T) {
	rec := captureSlowRTTLogs(t)

	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck
	s.endpoint = sharedconfig.EndpointTCP
	s.target = "example.com:443"
	slot := &transportSlot{idx: 3}
	s.slot = slot
	lim := &slowRTTLogLimiter{window: time.Minute, quota: 3}
	s.slowRTT = lim

	stats.ResetCounters()
	// 把打戳时间推前 600ms 即得到一个越界样本，无需真的等一个往返。
	s.bootstrapSentAt.Store(time.Now().Add(-600 * time.Millisecond).UnixNano())
	s.deliver(roundTripResult{
		resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))},
	})

	warns := rec.waitForWarn(time.Second)
	if len(warns) != 1 {
		t.Fatalf("got %d Warn records, want exactly 1: %v", len(warns), warns)
	}
	if got := lim.loggedCount(); got != 1 {
		t.Fatalf("limiter logged %d samples, want 1: the stream must report through the transport limiter", got)
	}
	attrs := assertSlowRTTWarn(t, warns[0])
	if attrs["origin"] != slowRTTSourceStream {
		t.Errorf("origin = %q, want %q", attrs["origin"], slowRTTSourceStream)
	}
	if attrs["endpoint"] != sharedconfig.EndpointTCP {
		t.Errorf("endpoint = %q, want %q", attrs["endpoint"], sharedconfig.EndpointTCP)
	}
	if attrs["proto"] != "tcp" {
		t.Errorf("proto = %q, want tcp", attrs["proto"])
	}
	if attrs["target"] != "example.com:443" {
		t.Errorf("target = %q, want example.com:443", attrs["target"])
	}
	if attrs["slot"] != "3" {
		t.Errorf("slot = %q, want 3", attrs["slot"])
	}
	if attrs["active_streams"] != "0" {
		t.Errorf("active_streams = %q, want 0 for a bare test slot", attrs["active_streams"])
	}
	if _, ok := attrs["slot_state"]; !ok {
		t.Error("slot_state is missing from the slow sample record")
	}
	if got := stats.Collect().RTTCount; got != 1 {
		t.Errorf("RTTCount = %d, want 1: a slow sample must still feed the EWMA", got)
	}
}

// TestLogSlowPathRTTSilentOnFastSample 验证健康样本不产生任何日志——
// 阈值只筛出真正需要归因的那些往返。
func TestLogSlowPathRTTSilentOnFastSample(t *testing.T) {
	rec := captureSlowRTTLogs(t)

	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck
	s.endpoint = sharedconfig.EndpointUDP
	s.target = "1.1.1.1:53"

	stats.ResetCounters()
	s.MarkBootstrapSent()
	s.deliver(roundTripResult{
		resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))},
	})

	if warns := rec.at(slog.LevelWarn); len(warns) != 0 {
		t.Fatalf("a fast sample produced %d Warn records, want 0: %v", len(warns), warns)
	}
	if got := stats.Collect().RTTCount; got != 1 {
		t.Fatalf("RTTCount = %d, want 1", got)
	}
}

// TestLogSlowPathRTTWithoutSlotOrLimiter 验证裸构造的流（没有槽位、也没有传输层
// 的限流器）不会 panic：慢样本照常打印，只是省略槽位属性、不做限流——限流是
// 日志噪声的策略问题，不该成为日志是否存在的开关。
func TestLogSlowPathRTTWithoutSlotOrLimiter(t *testing.T) {
	rec := captureSlowRTTLogs(t)

	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	stats.ResetCounters()
	s.bootstrapSentAt.Store(time.Now().Add(-time.Second).UnixNano())
	s.deliver(roundTripResult{
		resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))},
	})

	warns := rec.waitForWarn(time.Second)
	if len(warns) != 1 {
		t.Fatalf("got %d Warn records, want 1", len(warns))
	}
	attrs := assertSlowRTTWarn(t, warns[0])
	if _, ok := attrs["slot"]; ok {
		t.Errorf("slot = %q, want the attribute to be omitted for a nil slot", attrs["slot"])
	}
}

// newSlowProbeServer 启动一个探测端点：响应头准时到达，载荷推迟 bodyDelay。
// 吞吐量结论因此是"快"（载荷整块到达），但路径 RTT 包含那段延迟。
func newSlowProbeServer(t *testing.T, bodyDelay time.Duration) string {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(testProbePayloadSize))
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		time.Sleep(bodyDelay)
		_, _ = w.Write(make([]byte, testProbePayloadSize))
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestLogSlowPathRTTOnSlowProbe 验证后台探测的慢样本同样可见，并被标成 probe：
// 探测和请求都会推高托盘上的平均值，不标出来就会与真正慢的请求混为一谈。
func TestLogSlowPathRTTOnSlowProbe(t *testing.T) {
	rec := captureSlowRTTLogs(t)

	lim := &slowRTTLogLimiter{window: time.Minute, quota: 3}
	prober := &slotProber{
		serverURL:   newSlowProbeServer(t, 600*time.Millisecond),
		token:       "unused",
		payloadSize: testProbePayloadSize,
		slowRTT:     lim,
	}

	stats.ResetCounters()
	speed, verdict := prober.probe(context.Background(), newProbeSlot())
	if verdict != probeFast {
		t.Fatalf("verdict = %v, want probeFast (speed %v)", verdict, speed)
	}

	warns := rec.waitForWarn(time.Second)
	if len(warns) != 1 {
		t.Fatalf("got %d Warn records, want exactly 1: %v", len(warns), warns)
	}
	if got := lim.loggedCount(); got != 1 {
		t.Fatalf("limiter logged %d samples, want 1: the probe must report through the transport limiter", got)
	}
	attrs := assertSlowRTTWarn(t, warns[0])
	if attrs["origin"] != slowRTTSourceProbe {
		t.Errorf("origin = %q, want %q", attrs["origin"], slowRTTSourceProbe)
	}
	if attrs["endpoint"] != sharedconfig.EndpointProbe {
		t.Errorf("endpoint = %q, want %q", attrs["endpoint"], sharedconfig.EndpointProbe)
	}
	if attrs["proto"] != "probe" {
		t.Errorf("proto = %q, want probe", attrs["proto"])
	}
	if _, ok := attrs["target"]; ok {
		t.Errorf("target = %q, want the attribute to be omitted for a probe", attrs["target"])
	}
	if got := stats.Collect().RTTCount; got != 1 {
		t.Errorf("RTTCount = %d, want 1", got)
	}
}

// TestSlowPathRTTLogLineRendersWithRealHandler 守住自定义属性名与 slog 内建 source 键的
// 冲突：log.newReplaceAttrFunc 对该键做 *slog.Source 断言，同名属性会让生产 handler 渲染时 panic。
func TestSlowPathRTTLogLineRendersWithRealHandler(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Logger()
	log.SetLogger(slog.New(log.TextHandler(&buf, slog.LevelDebug)))
	t.Cleanup(func() { log.SetLogger(prev) })

	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck
	s.endpoint = sharedconfig.EndpointTCP
	s.target = "example.com:443"
	s.slot = &transportSlot{idx: 1}

	stats.ResetCounters()
	s.bootstrapSentAt.Store(time.Now().Add(-700 * time.Millisecond).UnixNano())
	s.deliver(roundTripResult{
		resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))},
	})

	line := buf.String()
	for _, want := range []string{
		"level=WARN",
		"slow path RTT sample",
		"origin=stream",
		"endpoint=/v3/tcp",
		"proto=tcp",
		"target=example.com:443",
		"slot=1",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("rendered log line is missing %q:\n%s", want, line)
		}
	}
}

// newSlowHeaderServer 启动一个把响应头推迟 headerDelay 的 HTTP/2 测试服务器：
// 引导往返因此包含这段延迟，而响应体本身没有任何问题。
func newSlowHeaderServer(t *testing.T, headerDelay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(headerDelay)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestHTTP2Transport_SlowBootstrapLogsRequestIdentity 端到端固定这条日志的用途：
// 托盘上的 RTT 变大时，日志必须指出是哪个请求（target）在哪条端点上慢，以及
// 它跑在哪个槽位上；健康的往返则保持静默。
func TestHTTP2Transport_SlowBootstrapLogsRequestIdentity(t *testing.T) {
	rec := captureSlowRTTLogs(t)
	// 服务端延迟 700ms，阈值 500ms：留出足够余量，使样本不可能因调度抖动落到阈值之下。
	srv := newSlowHeaderServer(t, 700*time.Millisecond)

	tr, err := New(Config{
		ServerURL: srv.URL,
		TLSConfig: &utls.Config{
			InsecureSkipVerify: true,
			NextProtos:         sharedconfig.NextProtos,
		},
		Timeouts: sharedconfig.Timeouts{Base: 5 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	stats.ResetCounters()
	stream, err := tr.Open(context.Background(), transport.OpenRequest{
		Endpoint:     sharedconfig.EndpointTCP,
		Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
		HighPriority: true,
		Target:       "slow.example.com:443",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close() //nolint:errcheck

	// 代理层在冲刷引导记录后打戳，此刻服务端还在延迟响应头。
	marker, ok := stream.(transport.BootstrapSentMarker)
	if !ok {
		t.Fatal("stream does not implement transport.BootstrapSentMarker")
	}
	marker.MarkBootstrapSent()

	warns := rec.waitForWarn(3 * time.Second)
	if len(warns) != 1 {
		t.Fatalf("got %d Warn records, want exactly 1: %v", len(warns), warns)
	}
	attrs := assertSlowRTTWarn(t, warns[0])
	if attrs["target"] != "slow.example.com:443" {
		t.Errorf("target = %q, want slow.example.com:443: the record must name the request", attrs["target"])
	}
	if attrs["endpoint"] != sharedconfig.EndpointTCP || attrs["proto"] != "tcp" {
		t.Errorf("endpoint/proto = %q/%q, want %s/tcp", attrs["endpoint"], attrs["proto"], sharedconfig.EndpointTCP)
	}
	if attrs["origin"] != slowRTTSourceStream {
		t.Errorf("origin = %q, want %q", attrs["origin"], slowRTTSourceStream)
	}
	// 影子检查：慢样本必须来自这次往返，而不是别处（槽位属性只在实际采样点补齐）。
	if _, ok := attrs["slot"]; !ok {
		t.Error("slot is missing: the record must say which connection carried the round trip")
	}
	if got := stats.Collect().RTTCount; got != 1 {
		t.Fatalf("RTTCount = %d, want 1", got)
	}

	// New -> Open -> 流：整条链路上必须是同一个限流器实例，否则请求侧的样本
	// 不受配额约束（限流就只覆盖了探测路径），健康循环的兜底冲刷也交代不了它们。
	h2, ok := tr.(*http2Transport)
	if !ok {
		t.Fatal("New must return *http2Transport")
	}
	if h2.slowRTT == nil {
		t.Fatal("New did not configure the slow RTT limiter")
	}
	if h2.lifecycle.slowRTT != h2.slowRTT {
		t.Error("the health loop holds a different limiter: its window flush would never report these samples")
	}
	if got := h2.slowRTT.loggedCount(); got != 1 {
		t.Errorf("limiter logged %d samples, want 1: the stream must report through the transport limiter", got)
	}

	t.Run("healthy round trip stays silent", func(t *testing.T) {
		fastSrv := newSlowHeaderServer(t, 0)
		fastTr, err := New(Config{
			ServerURL: fastSrv.URL,
			TLSConfig: &utls.Config{
				InsecureSkipVerify: true,
				NextProtos:         sharedconfig.NextProtos,
			},
			Timeouts: sharedconfig.Timeouts{Base: 5 * time.Second},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = fastTr.Close() })

		fastStream, err := fastTr.Open(context.Background(), transport.OpenRequest{
			Endpoint:     sharedconfig.EndpointUDP,
			Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
			HighPriority: false,
			Target:       "1.1.1.1:53",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer fastStream.Close() //nolint:errcheck

		if m, ok := fastStream.(transport.BootstrapSentMarker); ok {
			m.MarkBootstrapSent()
		}
		// Read 在结果落定后才返回，因此它返回时样本已经记录完毕。
		if _, err := io.ReadAll(fastStream); err != nil {
			t.Fatal(err)
		}
		if warns := rec.at(slog.LevelWarn); len(warns) != 1 {
			t.Fatalf("healthy round trip changed the Warn count to %d, want it to stay 1: %v", len(warns), warns)
		}
	})
}

// TestSlowRTTLogLimiterQuotaAndFlushSummary 守住配额与汇总：突发结束后没有新样本触发
// 窗口滚动，必须由健康循环的 flushDue 兜底交代，否则被压掉的越界样本无声消失。
func TestSlowRTTLogLimiterQuotaAndFlushSummary(t *testing.T) {
	rec := captureSlowRTTLogs(t)
	lim := &slowRTTLogLimiter{window: time.Minute, quota: 2}

	submitSlowSamples(lim, 5) // 600ms..604ms：前 2 条打印，后 3 条被压掉
	lim.log(1800*time.Millisecond, slowRTTSample{
		source:   slowRTTSourceStream,
		endpoint: sharedconfig.EndpointTCP,
		target:   "slowest.example.com:443",
		slot:     &transportSlot{idx: 9},
	})

	if got := len(rec.withMessage(msgSlowRTTSample)); got != 2 {
		t.Fatalf("got %d sample records, want 2 (the window quota): %v", got, rec.at(slog.LevelWarn))
	}
	if got := len(rec.withMessage(msgSlowRTTSummary)); got != 0 {
		t.Fatalf("got %d summary records before the window ended, want 0", got)
	}

	lim.flushDue(time.Now().Add(2 * time.Minute))

	summaries := rec.withMessage(msgSlowRTTSummary)
	if len(summaries) != 1 {
		t.Fatalf("got %d summary records after the window ended, want 1: %v", len(summaries), rec.at(slog.LevelWarn))
	}
	attrs := attrsOf(summaries[0])
	if attrs["suppressed"] != "4" {
		t.Errorf("suppressed = %q, want 4", attrs["suppressed"])
	}
	if attrs["worst_rtt"] != "1.8s" {
		t.Errorf("worst_rtt = %q, want 1.8s", attrs["worst_rtt"])
	}
	if attrs["worst_target"] != "slowest.example.com:443" {
		t.Errorf("worst_target = %q, want slowest.example.com:443", attrs["worst_target"])
	}
	if attrs["worst_endpoint"] != sharedconfig.EndpointTCP || attrs["worst_origin"] != slowRTTSourceStream {
		t.Errorf("worst_endpoint/worst_origin = %q/%q, want %s/%s",
			attrs["worst_endpoint"], attrs["worst_origin"], sharedconfig.EndpointTCP, slowRTTSourceStream)
	}
	if attrs["window"] != "1m0s" {
		t.Errorf("window = %q, want 1m0s", attrs["window"])
	}

	// 已经交代过的窗口不会重复汇总。
	lim.flushDue(time.Now().Add(4 * time.Minute))
	if got := len(rec.withMessage(msgSlowRTTSummary)); got != 1 {
		t.Fatalf("got %d summary records after a second flush, want 1", got)
	}
}

// TestSlowRTTLogLimiterSummaryRidesNextWindow 验证没有 flushDue 时汇总也不会丢：
// 窗口结束后到达的下一条样本先交代上一窗口被压掉的样本，再打印自己。
func TestSlowRTTLogLimiterSummaryRidesNextWindow(t *testing.T) {
	rec := captureSlowRTTLogs(t)
	// 窗口取得足够小以便在用例里真的过期，又不至于让"提交三条样本"跨窗口。
	const window = 200 * time.Millisecond
	lim := &slowRTTLogLimiter{window: window, quota: 1}

	submitSlowSamples(lim, 3) // 1 条打印 + 2 条被压掉
	time.Sleep(window + 50*time.Millisecond)
	lim.log(700*time.Millisecond, slowRTTSample{
		source:   slowRTTSourceStream,
		endpoint: sharedconfig.EndpointUDP,
		target:   "after.example.com:443",
		slot:     &transportSlot{idx: 1},
	})

	warns := rec.at(slog.LevelWarn)
	if len(warns) != 3 {
		t.Fatalf("got %d Warn records, want 3 (sample + summary + sample): %v", len(warns), warns)
	}
	if warns[0].Message != msgSlowRTTSample {
		t.Fatalf("first record = %q, want a sample", warns[0].Message)
	}
	if warns[1].Message != msgSlowRTTSummary {
		t.Fatalf("second record = %q, want the previous window's summary before the new sample", warns[1].Message)
	}
	if attrs := attrsOf(warns[1]); attrs["suppressed"] != "2" {
		t.Errorf("suppressed = %q, want 2", attrs["suppressed"])
	}
	if warns[2].Message != msgSlowRTTSample {
		t.Fatalf("third record = %q, want the new window's sample", warns[2].Message)
	}
	if attrs := attrsOf(warns[2]); attrs["target"] != "after.example.com:443" {
		t.Errorf("target = %q, want after.example.com:443", attrs["target"])
	}
}

// TestSlowRTTLogLimiterFastSamplesDoNotSpendQuota 验证阈值检查排在配额之前：
// 健康样本既不打印也不消耗配额，否则一段快速请求之后紧接着的越界样本会被
// 莫名其妙地压掉——而它恰恰是用户要看的那一条。
func TestSlowRTTLogLimiterFastSamplesDoNotSpendQuota(t *testing.T) {
	rec := captureSlowRTTLogs(t)
	lim := &slowRTTLogLimiter{window: time.Minute, quota: 2}

	for range 100 {
		lim.log(5*time.Millisecond, slowRTTSample{
			source:   slowRTTSourceStream,
			endpoint: sharedconfig.EndpointTCP,
			target:   "fast.example.com:443",
		})
	}
	submitSlowSamples(lim, 2)

	if got := len(rec.at(slog.LevelWarn)); got != 2 {
		t.Fatalf("got %d Warn records, want 2 (only the slow samples): %v", got, rec.at(slog.LevelWarn))
	}
	if got := lim.loggedCount(); got != 2 {
		t.Fatalf("limiter logged %d samples, want 2: fast samples must not spend the quota", got)
	}
}
