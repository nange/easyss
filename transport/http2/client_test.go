package http2

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
)

func TestUTLSDialUsesHTTP2(t *testing.T) {
	protoCh := make(chan string, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protoCh <- r.Proto
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	slot := newSlot(&utls.Config{
		InsecureSkipVerify: true,
		NextProtos:         sharedconfig.NextProtos,
	}, time.Second, nil, time.Minute)
	t.Cleanup(slot.t.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodPost, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := slot.t.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	_, _ = io.Copy(io.Discard, resp.Body)

	if got := <-protoCh; got != "HTTP/2.0" {
		t.Fatalf("server got %s, want HTTP/2.0", got)
	}
}

// TestHTTP2Transport_Non200StatusIsRejected 验证握手以非 200 状态应答
// （例如 408 Request Timeout）时会快速失败并返回 HandshakeRejectedError，
// 而不是把拒绝正文暴露给记录读取器。
func TestHTTP2Transport_Non200StatusIsRejected(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusRequestTimeout)
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tr, err := New(Config{
		ServerURL: srv.URL,
		TLSConfig: &utls.Config{
			InsecureSkipVerify: true,
			NextProtos:         sharedconfig.NextProtos,
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	stream, err := tr.Open(context.Background(), transport.OpenRequest{
		Endpoint:     sharedconfig.EndpointTCP,
		Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
		HighPriority: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close() //nolint:errcheck

	buf := make([]byte, 16)
	_, err = stream.Read(buf)
	if err == nil {
		t.Fatal("expected a rejection error, got nil")
	}
	if !transport.IsHandshakeRejected(err) {
		t.Fatalf("expected HandshakeRejectedError, got: %v", err)
	}
}

// TestHTTP2Transport_200StatusReadsBody 验证 200 响应会作为普通的可读正文呈现。
func TestHTTP2Transport_200StatusReadsBody(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tr, err := New(Config{
		ServerURL: srv.URL,
		TLSConfig: &utls.Config{
			InsecureSkipVerify: true,
			NextProtos:         sharedconfig.NextProtos,
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	stream, err := tr.Open(context.Background(), transport.OpenRequest{
		Endpoint:     sharedconfig.EndpointTCP,
		Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
		HighPriority: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close() //nolint:errcheck

	body, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Fatalf("got %q, want %q", body, "hello")
	}
}

// TestHTTP2Transport_GrowEventAttribution 验证槽位扩容归因于触发它的请求：
// 全新 transport 上的首次 Open 激活 priority 池（首次激活 2 个槽位），
// 并恰好记录一条携带该请求 endpoint 与 target 的 GrowEvent；
// 随后仍有层级容量时的 Open 不再记录。
func TestHTTP2Transport_GrowEventAttribution(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tr, err := New(Config{
		ServerURL: srv.URL,
		TLSConfig: &utls.Config{
			InsecureSkipVerify: true,
			NextProtos:         sharedconfig.NextProtos,
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	open := func(target string) {
		t.Helper()
		stream, err := tr.Open(context.Background(), transport.OpenRequest{
			Endpoint:     sharedconfig.EndpointTCP,
			Salt:         "dGVzdHNhbHR0ZXN0c2FsdA",
			HighPriority: true,
			Target:       target,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, stream)
		stream.Close() //nolint:errcheck
	}

	// 首条流：触发 priority 池的首次激活（+2）。
	open("example.com:443")
	evs := tr.Stats().GrowEvents
	if len(evs) != 1 {
		t.Fatalf("GrowEvents = %d, want 1 after the triggering Open", len(evs))
	}
	ev := evs[0]
	if ev.Pool != "priority" {
		t.Fatalf("event pool = %q, want priority", ev.Pool)
	}
	if ev.Live != 2 {
		t.Fatalf("event live = %d, want 2 (first activation)", ev.Live)
	}
	if ev.Endpoint != sharedconfig.EndpointTCP {
		t.Fatalf("event endpoint = %q, want %q", ev.Endpoint, sharedconfig.EndpointTCP)
	}
	if ev.Target != "example.com:443" {
		t.Fatalf("event target = %q, want example.com:443", ev.Target)
	}

	// 第二条流：池有空闲容量，无生长，无新事件。
	open("example.org:443")
	if got := len(tr.Stats().GrowEvents); got != 1 {
		t.Fatalf("GrowEvents = %d, want 1 (no growth for the second Open)", got)
	}
}

func TestTrackReadMarksSlotHeavy(t *testing.T) {
	// 快路径：大传输一旦越过累计大小阈值即被标记。
	t.Run("fast large transfer marks at size threshold", func(t *testing.T) {
		slot := &transportSlot{}
		stream := &http2Stream{slot: slot, startTime: time.Now()}

		// 低于快阈值且对慢路径而言太年轻：不标记。
		stream.trackRead(sharedconfig.HeavyStreamThresholdBytes - 1)
		if slot.heavy.Load() != 0 || stream.heavyState.Load() != heavyIdle {
			t.Fatalf("marked heavy before threshold: slot.heavy=%d state=%d", slot.heavy.Load(), stream.heavyState.Load())
		}

		// 越过快阈值：恰好标记一次。
		stream.trackRead(2)
		if slot.heavy.Load() != 1 || stream.heavyState.Load() != heavyMarked {
			t.Fatalf("expected heavy mark after threshold: slot.heavy=%d state=%d", slot.heavy.Load(), stream.heavyState.Load())
		}
		if slot.bytesRecv.Load() != int64(sharedconfig.HeavyStreamThresholdBytes+1) {
			t.Fatalf("bytesRecv not accumulated: %d", slot.bytesRecv.Load())
		}
		if slot.connBytes.Load() != slot.bytesRecv.Load() {
			t.Fatalf("connBytes = %d, want %d", slot.connBytes.Load(), slot.bytesRecv.Load())
		}

		// 后续传输不得重复标记。
		stream.trackRead(64 * 1024)
		if slot.heavy.Load() != 1 {
			t.Fatalf("heavy marked more than once: %d", slot.heavy.Load())
		}

		// 流结束时释放：镜像 Open 中的 doneOnce 逻辑。
		stream.releaseHeavy()
		if slot.heavy.Load() != 0 {
			t.Fatalf("heavy mark not released: %d", slot.heavy.Load())
		}
		if stream.heavyState.Load() != heavyReleased {
			t.Fatalf("state = %d, want released", stream.heavyState.Load())
		}
	})

	// 慢路径：链路不佳时，即使不足 1MB 的传输也会长期存活，
	// 因此流存活足够久之后也必须被标记。
	t.Run("slow transfer marks after min age", func(t *testing.T) {
		slot := &transportSlot{}
		stream := &http2Stream{
			slot:      slot,
			startTime: time.Now().Add(-sharedconfig.HeavyStreamMinAge - time.Second),
		}

		// 低于慢阈值：无论存活多久都不标记。
		stream.trackRead(sharedconfig.HeavyStreamSlowThresholdBytes - 1)
		if slot.heavy.Load() != 0 {
			t.Fatalf("marked heavy below slow threshold: %d", slot.heavy.Load())
		}

		// 达到或超过慢阈值且存活足够久：标记一次。
		stream.trackRead(1024)
		if slot.heavy.Load() != 1 || stream.heavyState.Load() != heavyMarked {
			t.Fatalf("expected heavy mark on slow path: slot.heavy=%d state=%d", slot.heavy.Load(), stream.heavyState.Load())
		}
	})

	// 低于快阈值且年轻的流不得被标记。
	t.Run("young stream below fast threshold not marked", func(t *testing.T) {
		slot := &transportSlot{}
		stream := &http2Stream{slot: slot, startTime: time.Now()}

		stream.trackRead(sharedconfig.HeavyStreamSlowThresholdBytes)
		if slot.heavy.Load() != 0 {
			t.Fatalf("young stream marked heavy: %d", slot.heavy.Load())
		}
	})

	// nil 槽位是无操作（例如测试构造的流）。
	t.Run("nil slot no-op", func(t *testing.T) {
		noSlot := &http2Stream{}
		noSlot.trackRead(sharedconfig.HeavyStreamThresholdBytes)
		if noSlot.heavyState.Load() != heavyIdle {
			t.Fatal("nil slot must not be marked heavy")
		}
	})

	// 在流从未够格成为 heavy 之前释放，绝不能增加槽位计数器，
	// 之后的传输也不得泄漏它。
	t.Run("release before marking never increments", func(t *testing.T) {
		slot := &transportSlot{}
		stream := &http2Stream{slot: slot, startTime: time.Now()}
		stream.releaseHeavy()
		stream.trackRead(sharedconfig.HeavyStreamThresholdBytes)
		if slot.heavy.Load() != 0 {
			t.Fatalf("heavy marked after release: %d", slot.heavy.Load())
		}
		if stream.heavyState.Load() != heavyReleased {
			t.Fatalf("state = %d, want released", stream.heavyState.Load())
		}
		// 双重释放不得把计数器减到零以下。
		stream.releaseHeavy()
		if slot.heavy.Load() != 0 {
			t.Fatalf("double release changed counter: %d", slot.heavy.Load())
		}
	})
}

// TestHTTP2Transport_WarmUp 验证两个调度池都被激活，并通过真实的探测请求
// 建立各自的首条连接：WarmUp 之后每个池报告 2 个存活槽位（首次激活），
// 且服务器为每个池各服务恰好一次探测，因此任一类的首条真实流
// 都复用已建立的连接。
func TestHTTP2Transport_WarmUp(t *testing.T) {
	ts, token := newProbeServer(t)

	tr, err := New(Config{
		ServerURL:  ts.URL,
		TLSConfig:  &utls.Config{InsecureSkipVerify: true, NextProtos: sharedconfig.NextProtos},
		Timeout:    time.Second,
		ProbeToken: token,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	stats.ResetCounters()
	if err := tr.WarmUp(context.Background()); err != nil {
		t.Fatalf("WarmUp: %v", err)
	}

	st := tr.Stats()
	if st.PriorityConns != 2 {
		t.Fatalf("PriorityConns = %d, want 2 (priority pool first activation)", st.PriorityConns)
	}
	if st.BulkConns != 2 {
		t.Fatalf("BulkConns = %d, want 2 (bulk pool first activation)", st.BulkConns)
	}
	if got := stats.Collect().ServerProbes; got != 2 {
		t.Fatalf("server served %d probe requests, want 2 (one per pool)", got)
	}
}

// TestHTTP2Transport_WarmUpFailsWhenUnreachable 验证失败的探测（服务器不可达）
// 以错误形式呈现，由调用方决定是否吞掉。错误指明保持冷态的池，
// 并包装哨兵判定，使调用方可以分类失败而不是匹配文本。
func TestHTTP2Transport_WarmUpFailsWhenUnreachable(t *testing.T) {
	ts, token := newProbeServer(t)
	deadURL := ts.URL
	ts.Close() // connection refused from now on

	tr, err := New(Config{
		ServerURL:  deadURL,
		TLSConfig:  &utls.Config{InsecureSkipVerify: true, NextProtos: sharedconfig.NextProtos},
		Timeout:    time.Second,
		ProbeToken: token,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	err = tr.WarmUp(context.Background())
	if err == nil {
		t.Fatal("expected an error when the server is unreachable, got nil")
	}
	if !errors.Is(err, errProbeNotConfirmed) {
		t.Errorf("error = %v, want it to wrap errProbeNotConfirmed", err)
	}
	if !strings.Contains(err.Error(), "priority") {
		t.Errorf("error = %v, want it to name the pool that failed", err)
	}
}
