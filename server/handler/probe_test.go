package handler

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/crypto"
)

// h2Request builds an HTTP/2 request; httptest.NewRequest defaults to
// HTTP/1.1, which the probe handler (like the proxy handler) rejects with
// the fallback page.
func h2Request(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	return req
}

func newTestProbeHandler(t *testing.T) (*ProbeHandler, string, []byte) {
	t.Helper()
	masterKey, err := crypto.DeriveMasterKey("test-password")
	if err != nil {
		t.Fatal(err)
	}
	token, err := crypto.ProbeToken(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4096)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatal(err)
	}
	h, err := NewProbeHandler(masterKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	return h, token, payload
}

func TestProbeHandlerValidToken(t *testing.T) {
	h, token, payload := newTestProbeHandler(t)

	req := h2Request(http.MethodGet, "/v3/probe")
	req.Header.Set("x-es", token)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", ct)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	if cl := rr.Header().Get("Content-Length"); cl != "4096" {
		t.Fatalf("Content-Length = %q, want 4096", cl)
	}
	if !bytes.Equal(rr.Body.Bytes(), payload) {
		t.Fatal("body differs from the pre-generated payload")
	}

	// A second request must serve the same buffer.
	req2 := h2Request(http.MethodGet, "/v3/probe")
	req2.Header.Set("x-es", token)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if !bytes.Equal(rr2.Body.Bytes(), payload) {
		t.Fatal("second response differs from the pre-generated payload")
	}
}

func TestProbeHandlerRejectsInvalidToken(t *testing.T) {
	h, _, _ := newTestProbeHandler(t)

	cases := []struct {
		name  string
		token string
	}{
		{"missing token", ""},
		{"garbage token", "not-a-valid-token"},
		{"wrong token", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := h2Request(http.MethodGet, "/v3/probe")
			if tc.token != "" {
				req.Header.Set("x-es", tc.token)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 fallback", rr.Code)
			}
			if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Fatalf("Content-Type = %q, want fallback HTML", ct)
			}
			if rr.Body.Len() == 4096 {
				t.Fatal("fallback response must not contain the probe payload")
			}
		})
	}
}

func TestProbeHandlerRejectsHTTP1(t *testing.T) {
	h, token, _ := newTestProbeHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v3/probe", nil) // HTTP/1.1
	req.Header.Set("x-es", token)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want fallback HTML for HTTP/1.1", ct)
	}
}

func TestProbeHandlerRateLimit(t *testing.T) {
	h, token, _ := newTestProbeHandler(t)

	// Drain the per-IP bucket (capacity 100), then the next request is
	// rejected with 429.
	ip := "203.0.113.7"
	for i := 0; i < 100; i++ {
		if !h.limiter.Allow(ip) {
			t.Fatalf("bucket drained earlier than expected at request %d", i+1)
		}
	}

	req := h2Request(http.MethodGet, "/v3/probe")
	req.Header.Set("x-es", token)
	req.RemoteAddr = ip + ":12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
}
