package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// recordingHandler 记录每条日志的级别与消息，用于断言日志降噪的回归。
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) at(level slog.Level) []slog.Record {
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

// cancelledDialError 复现 net 在 context 失效时返回的取消错误（"operation was
// canceled"，其 Is(context.Canceled) 为真）。net 没有导出该类型，因此按同样
// 的字符串与 Is 语义重建，用于回归测试。
type cancelledDialError struct{}

func (cancelledDialError) Error() string { return "operation was canceled" }
func (cancelledDialError) Is(target error) bool {
	return target == context.Canceled
}

// TestIsTransientStreamError 固定"对端已离开该流"的判定：客户端正常拆除
// （HTTP/2 RST_STREAM(CANCEL)、请求体已被关闭）、传输层断开、中继空闲超时
// 都属于预期路径，必须与真正的故障区分开。这里出现的字符串都取自真实运行
// 日志（见 issue 报告）与 net/http/http2 的公开错误文本。
func TestIsTransientStreamError(t *testing.T) {
	transient := []struct {
		name string
		err  error
	}{
		{"http2 stream cancel", errors.New(`crypto: read cipher_len: stream error: stream ID 13; CANCEL`)},
		{"http2 stream reset", errors.New(`crypto: read cipher_len: stream error: stream ID 7; RST_STREAM`)},
		{"http2 stream closed", errors.New("crypto: write record: http2: stream closed")},
		{"http2 connection lost", errors.New("crypto: read cipher_len: http2: client connection lost")},
		{"poisoned request body", errors.New("crypto: read cipher_len: http: invalid Read on closed Body")},
		{"connection reset", errors.New("read tcp 10.0.0.1:443->10.0.0.2:5512: read: connection reset by peer")},
		{"broken pipe", errors.New("write tcp: broken pipe")},
		{"relay idle timeout", errors.New("tcp stream idle timeout after 2m0s")},
		{"relay drained", errors.New("stream drained: idle for 5s while the slot is due for eviction")},
		{"client gone after cancel", errClientGone},
		{"closed conn", net.ErrClosed},
		{"wrapped errClientGone", fmt.Errorf("dial: %w", errClientGone)},
		{"io closed pipe", io.ErrClosedPipe},
		{"body read after close", errors.New("http: invalid Read on closed Body")},
	}

	for _, tt := range transient {
		t.Run("transient/"+tt.name, func(t *testing.T) {
			if !isTransientStreamError(tt.err) {
				t.Fatalf("isTransientStreamError(%v) = false, want true", tt.err)
			}
		})
	}

	permanent := []struct {
		name string
		err  error
	}{
		{"dial refused", errors.New("dial tcp 93.184.216.34:443: connect: connection refused")},
		{"dial timeout", errors.New("dial tcp 93.184.216.34:443: i/o timeout")},
		{"ssrf rejection", errors.New("ssrf: rejected lan destination 192.168.1.1")},
		{"decrypt failure", errors.New("crypto: decrypt record: cipher: message authentication failed")},
		{"no route", errors.New("dial tcp 2001:db8::1:443: connect: network is unreachable")},
		// 取消的拨号错误满足 errors.Is(err, context.Canceled)，但不能因此被当作
		// 客户端拆除：它同样可能是真正的拨号故障。只有 dialOutbound 显式标记的
		// errClientGone 才代表客户端离开。
		{"canceled dial without the client-gone label", &net.OpError{Op: "dial", Net: "tcp4", Err: cancelledDialError{}}},
		{"nil", nil},
	}

	for _, tt := range permanent {
		t.Run("permanent/"+tt.name, func(t *testing.T) {
			if isTransientStreamError(tt.err) {
				t.Fatalf("isTransientStreamError(%v) = true, want false", tt.err)
			}
		})
	}
}

// TestIsTransientStreamErrorCancelledDial 是"客户端拆除期间拨号被 context 取消"
// 的回归测试：net 把取消转成未导出的取消错误（"operation was canceled"），而
// 它的 Is(context.Canceled) 为真。这一点会让 errors.Is(err, context.Canceled)
// 成立，因此 client-gone 必须由 dialOutbound 用 errClientGone 显式标记，
// 而不是依赖字符串匹配去猜。
func TestIsTransientStreamErrorCancelledDial(t *testing.T) {
	dialErr := &net.OpError{Op: "dial", Net: "tcp4", Err: cancelledDialError{}}
	if isTransientStreamError(dialErr) {
		t.Fatalf("the raw canceled-dial error must not be classified on its own: %v", dialErr)
	}

	ctx, cancel := context.WithCancel(t.Context())
	d := &probeNetDialer{
		fail: func(string) bool { cancel(); return true },
		err:  dialErr,
	}
	if _, err := dialOutbound(ctx, d, "tcp", testPublicV4+":443", netip.MustParseAddr(testPublicV4)); !errors.Is(err, errClientGone) {
		t.Fatalf("dialOutbound = %v, want errClientGone once the caller's context is gone", err)
	}
	if !isTransientStreamError(errClientGone) {
		t.Fatal("errClientGone must be classified as transient")
	}
}

// TestLogHandlerResult 是针对"每关闭一个连接就刷一条 Info 错误"的回归测试：
// 客户端正常拆除（stream CANCEL）必须降到 Debug 并计入 stream_cancels，
// 而真正的目标侧故障仍然留在 Info 且带 err=。
func TestLogHandlerResult(t *testing.T) {
	rec := &recordingHandler{}
	prev := log.Logger()
	log.SetLogger(slog.New(rec))
	t.Cleanup(func() { log.SetLogger(prev) })

	cancelErr := errors.New("crypto: read cipher_len: stream error: stream ID 13; CANCEL")

	stats.ResetCounters()
	logHandlerResult(cancelErr, "avatars.githubusercontent.com:443", "/v3/tcp", "1.2.3.4:5678")

	if got := len(rec.at(slog.LevelInfo)); got != 0 {
		t.Fatalf("a cancelled stream produced %d Info records, want 0: %v", got, rec.at(slog.LevelInfo))
	}
	debugs := rec.at(slog.LevelDebug)
	if len(debugs) != 1 {
		t.Fatalf("got %d Debug records, want 1", len(debugs))
	}
	if !strings.Contains(debugs[0].Message, "handler finished") {
		t.Fatalf("message = %q, want it to mention the finished handler", debugs[0].Message)
	}
	if snap := stats.Collect(); snap.ServerStreamCancels != 1 {
		t.Fatalf("ServerStreamCancels = %d, want 1", snap.ServerStreamCancels)
	}

	// 真正的故障保持 Info，并且带上可以定位目标的属性。
	rec.records = nil
	dialErr := errors.New(`dial tcp 93.184.216.34:443: connect: connection refused`)
	logHandlerResult(dialErr, "example.com:443", "/v3/tcp", "1.2.3.4:5678")

	infos := rec.at(slog.LevelInfo)
	if len(infos) != 1 {
		t.Fatalf("got %d Info records for a real failure, want 1", len(infos))
	}
	if !strings.Contains(infos[0].Message, "handler finished with error") {
		t.Fatalf("message = %q, want the error variant", infos[0].Message)
	}
	attrs := map[string]string{}
	infos[0].Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	for _, key := range []string{"target", "endpoint", "client", "err"} {
		if attrs[key] == "" {
			t.Errorf("Info record is missing the %q attribute: %v", key, attrs)
		}
	}
	if snap := stats.Collect(); snap.ServerStreamCancels != 1 {
		t.Fatalf("a real failure must not count as a stream cancel: %d", snap.ServerStreamCancels)
	}
}
