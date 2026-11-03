package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/nange/easyss/v3/transport"
)

func TestClassifyHandshakeReject(t *testing.T) {
	t.Parallel()

	pageErr := &transport.ServerAnsweredWithPageError{ContentType: "text/html"}
	tests := []struct {
		name string
		err  error
		want HandshakeRejectKind
		ok   bool
	}{
		{name: "nil", err: nil},
		{name: "network error", err: errors.New("connection reset by peer")},
		{name: "context deadline", err: context.DeadlineExceeded},
		{name: "server page", err: pageErr, want: RejectNotTunnel, ok: true},
		{
			name: "wrapped server page",
			err:  fmt.Errorf("crypto: read cipher_len: %w", pageErr),
			want: RejectNotTunnel,
			ok:   true,
		},
		{
			name: "non-encrypted payload",
			err:  fmt.Errorf("%w: server returned a non-encrypted payload", ErrServerRejectedHandshake),
			want: RejectNotTunnel,
			ok:   true,
		},
		{
			name: "endpoint mismatch",
			err:  &transport.HandshakeRejectedError{StatusCode: http.StatusNotFound},
			want: RejectEndpointMismatch,
			ok:   true,
		},
		{
			name: "method not allowed",
			err:  &transport.HandshakeRejectedError{StatusCode: http.StatusMethodNotAllowed},
			want: RejectMethodNotAllowed,
			ok:   true,
		},
		{
			name: "timeout",
			err:  &transport.HandshakeRejectedError{StatusCode: http.StatusRequestTimeout},
			want: RejectTimeout,
			ok:   true,
		},
		{
			name: "rate limited",
			err:  &transport.HandshakeRejectedError{StatusCode: http.StatusTooManyRequests},
			want: RejectRateLimited,
			ok:   true,
		},
		{
			name: "bad request",
			err:  &transport.HandshakeRejectedError{StatusCode: http.StatusBadRequest},
			want: RejectBadRequest,
			ok:   true,
		},
		{
			name: "server error",
			err:  &transport.HandshakeRejectedError{StatusCode: http.StatusInternalServerError},
			want: RejectServerError,
			ok:   true,
		},
		{
			name: "other status",
			err:  &transport.HandshakeRejectedError{StatusCode: http.StatusTeapot},
			want: RejectOther,
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := classifyHandshakeReject(tt.err)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("classifyHandshakeReject(%v) = (%q, %v), want (%q, %v)",
					tt.err, got, ok, tt.want, tt.ok)
			}
		})
	}
}

// 全局 logger 是进程级状态，本用例不能并行。
func TestHandshakeRejectorWarnsOncePerWindow(t *testing.T) {
	logs := captureLogs(t)

	now := time.Unix(1_700_000_000, 0)
	var r handshakeRejector
	r.now = func() time.Time { return now }

	pageErr := &transport.ServerAnsweredWithPageError{ContentType: "text/html"}
	for range 3 {
		r.report("example.com:443", "https://1.2.3.4:443", pageErr)
	}

	if got := logs.count(slog.LevelWarn, "[STREAM] handshake rejected"); got != 1 {
		t.Fatalf("got %d Warn records in the window, want 1", got)
	}
	if got := logs.attr(slog.LevelWarn, "[STREAM] handshake rejected", "kind"); got != string(RejectNotTunnel) {
		t.Fatalf("kind = %q, want %q", got, RejectNotTunnel)
	}
	if got := logs.attr(slog.LevelWarn, "[STREAM] handshake rejected", "server"); got != "https://1.2.3.4:443" {
		t.Fatalf("server = %q, want the configured server address", got)
	}

	// 窗口过后的第一条必须重新留痕，并把窗口内折叠的次数带出来。
	now = now.Add(rejectLogWindow)
	r.report("example.com:443", "https://1.2.3.4:443", pageErr)
	if got := logs.count(slog.LevelWarn, "[STREAM] handshake rejected"); got != 2 {
		t.Fatalf("got %d Warn records after the window, want 2", got)
	}
	if got := lastLogAttr(logs, slog.LevelWarn, "[STREAM] handshake rejected", "suppressed"); got != "2" {
		t.Fatalf("suppressed = %q, want 2", got)
	}
}

// lastLogAttr 取最后一条匹配记录的属性：窗口内的 Warn 有多条时，被折叠的次数只
// 出现在最新的那条上。
func lastLogAttr(h *recordHandler, level slog.Level, msg, key string) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, r := range slices.Backward(h.records) {
		if r.Level != level || r.Message != msg {
			continue
		}
		var got string
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == key {
				got = a.Value.String()
				return false
			}
			return true
		})
		return got
	}
	return ""
}

// 全局 logger 是进程级状态，本用例不能并行。
func TestHandshakeRejectorNotifiesOnlyOnTransitions(t *testing.T) {
	captureLogs(t)

	now := time.Unix(1_700_000_000, 0)
	var r handshakeRejector
	r.now = func() time.Time { return now }

	var (
		rejected  []HandshakeReject
		recovered int
	)
	r.setObserver(func(j HandshakeReject) { rejected = append(rejected, j) }, func() { recovered++ })

	pageErr := &transport.ServerAnsweredWithPageError{ContentType: "text/html"}
	r.report("example.com:443", "https://1.2.3.4:443", pageErr)
	r.report("example.com:443", "https://1.2.3.4:443", pageErr)
	if len(rejected) != 1 {
		t.Fatalf("observer called %d times for one failure episode, want 1", len(rejected))
	}
	if rejected[0].Kind != RejectNotTunnel {
		t.Fatalf("kind = %q, want %q", rejected[0].Kind, RejectNotTunnel)
	}

	// 窗口到期只影响日志：同一次失败 episode 内不得重新弹通知。
	now = now.Add(rejectLogWindow)
	r.report("example.com:443", "https://1.2.3.4:443", pageErr)
	if len(rejected) != 1 {
		t.Fatalf("window expiry re-notified the observer (%d calls), want 1", len(rejected))
	}

	r.recovered()
	r.recovered()
	if recovered != 1 {
		t.Fatalf("recovered observer called %d times, want 1", recovered)
	}

	// 恢复后再次失败是一次新事件，必须重新通知。
	r.report("example.com:443", "https://1.2.3.4:443",
		&transport.HandshakeRejectedError{StatusCode: http.StatusTooManyRequests})
	if len(rejected) != 2 || rejected[1].Kind != RejectRateLimited {
		t.Fatalf("rejected = %+v, want a second notification for %q", rejected, RejectRateLimited)
	}
}

// 全局 logger 是进程级状态，本用例不能并行。
func TestHandshakeRejectorClassifyRecoversOnSuccess(t *testing.T) {
	captureLogs(t)

	var (
		r         handshakeRejector
		recovered int
	)
	r.setObserver(nil, func() { recovered++ })

	r.report("example.com:443", "https://1.2.3.4:443",
		&transport.HandshakeRejectedError{StatusCode: http.StatusNotFound})
	if err := r.classify("example.com:443", "https://1.2.3.4:443", nil); err != nil {
		t.Fatalf("classify(nil) = %v, want nil", err)
	}
	if recovered != 1 {
		t.Fatalf("a successful first read must clear the alert, recovered = %d", recovered)
	}
}
