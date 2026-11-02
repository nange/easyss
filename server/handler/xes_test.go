package handler

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
)

// 超过 22 字符的输入仍可能是合法 base64：长度预检查一旦挪到解码之后，
// 超长头会先被解码（1MB 头约 750KB 缓冲），这些用例就会拿到 nil error。
func TestDecodeXESRejectsBeforeDecoding(t *testing.T) {
	for _, s := range []string{
		"",
		strings.Repeat("A", xesSaltB64Len-1),
		strings.Repeat("A", xesSaltB64Len+1),
		strings.Repeat("A", 64<<10),
		strings.Repeat("A", 1<<20),
	} {
		if _, err := decodeXES(s); err == nil {
			t.Errorf("decodeXES(%d chars) succeeded, want rejection by length", len(s))
		}
	}

	want := bytes.Repeat([]byte{0x5a}, 16)
	b, err := decodeXES(base64.RawURLEncoding.EncodeToString(want))
	if err != nil || !bytes.Equal(b, want) {
		t.Fatalf("valid 22-char header: bytes=%d err=%v", len(b), err)
	}
	if _, err := decodeXES(strings.Repeat("!", xesSaltB64Len)); err == nil {
		t.Error("22 invalid base64url characters decoded without error")
	}
}

// 超长 x-es 头在握手与探测路径上都只算畸形头：得到伪装首页，不进入限流与 salt 缓存。
func TestOversizedXESHeaderFallsBack(t *testing.T) {
	huge := strings.Repeat("A", 1<<20)

	proxy := NewProxyHandler(ProxyHandlerConfig{
		MasterKey: masterKeyForTest(),
		Timeouts:  config.NewTimeouts(time.Second),
	})
	req := h2Request(http.MethodPost, config.EndpointTCP)
	req.Header.Set("x-es", huge)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	requireFallbackHTML(t, rec)

	probe, _, _ := newTestProbeHandler(t)
	probeReq := h2Request(http.MethodGet, "/v3/probe")
	probeReq.Header.Set("x-es", huge)
	probeRec := httptest.NewRecorder()
	probe.ServeHTTP(probeRec, probeReq)
	requireFallbackHTML(t, probeRec)
}

func requireFallbackHTML(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 fallback", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html fallback", ct)
	}
}
