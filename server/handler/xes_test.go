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
	"github.com/nange/easyss/v3/crypto"
)

// 超长输入仍是合法 base64：长度预检查一旦挪到解码之后，超长头会先被解码（1MB 头约 750KB 缓冲）。
// 返回值看不出解码是否发生，顺序由下面的分配断言守住。
func TestDecodeXESRejectsBeforeDecoding(t *testing.T) {
	huge := strings.Repeat("A", 1<<20)
	for _, s := range []string{
		"",
		strings.Repeat("A", xesSaltB64Len-1),
		strings.Repeat("A", xesSaltB64Len+1),
		strings.Repeat("A", 64<<10),
		huge,
	} {
		if _, err := decodeXES(s); err == nil {
			t.Errorf("decodeXES(%d chars) succeeded, want rejection by length", len(s))
		}
	}

	// 只断言返回 error 抓不到顺序倒退：先解码再按解码长度校验同样报错，分配才是可观测差异。
	if n := testing.AllocsPerRun(10, func() { _, _ = decodeXES(huge) }); n != 0 {
		t.Errorf("length-rejected header decoded anyway: %v allocs/op", n)
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

// 上限（MaxHeaderBytes）量级的 x-es 在握手与探测路径上都只算畸形头：得到伪装首页，而不是
// 进入握手等待（408）或限流（429）。
func TestOversizedXESHeaderFallsBack(t *testing.T) {
	huge := strings.Repeat("A", config.ServerMaxHeaderBytes)

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

// 22 与 crypto 层的 salt / 能力令牌编码长度同源：那边一改，长度预检查会把所有合法握手
// 拒成伪装页，这里失败比线上全量回落更早暴露。
func TestXESLengthMatchesCryptoSalt(t *testing.T) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.RawURLEncoding.EncodedLen(len(salt)); got != xesSaltB64Len {
		t.Fatalf("crypto salt encodes to %d chars, x-es precheck expects %d", got, xesSaltB64Len)
	}
	token, err := crypto.ProbeToken(masterKeyForTest())
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != xesSaltB64Len {
		t.Fatalf("probe token is %d chars, x-es precheck expects %d", len(token), xesSaltB64Len)
	}
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
