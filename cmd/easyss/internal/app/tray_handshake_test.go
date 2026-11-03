//go:build !headless

package app

import (
	"strings"
	"testing"

	"github.com/nange/easyss/v3/client/proxy"
)

// TestFriendlyHandshakeRejectCoversKinds 固定每种可识别的拒绝原因都有自己的可操作
// 提示：托盘通知是用户唯一能看到的排查方向，退化成同一句兜底等于没有提示。
func TestFriendlyHandshakeRejectCoversKinds(t *testing.T) {
	kinds := []proxy.HandshakeRejectKind{
		proxy.RejectNotTunnel,
		proxy.RejectEndpointMismatch,
		proxy.RejectMethodNotAllowed,
		proxy.RejectRateLimited,
		proxy.RejectTimeout,
		proxy.RejectBadRequest,
		proxy.RejectServerError,
	}

	seen := make(map[string]proxy.HandshakeRejectKind, len(kinds))
	for _, kind := range kinds {
		msg := friendlyHandshakeReject(kind)
		if msg == "" {
			t.Fatalf("%s: empty message", kind)
		}
		if prev, ok := seen[msg]; ok {
			t.Fatalf("%s and %s share the same message", prev, kind)
		}
		seen[msg] = kind
	}

	fallback := friendlyHandshakeReject(proxy.HandshakeRejectKind("unknown"))
	if fallback == "" || !strings.Contains(fallback, "口令") {
		t.Fatalf("fallback message = %q, want it to point at the password", fallback)
	}
	if _, ok := seen[fallback]; ok {
		t.Fatal("an unknown kind must not reuse a known kind's message")
	}
}
