package handler

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/stretchr/testify/require"
)

// buildBootstrapRecord produces the encrypted bootstrap record a real easyss
// client would send (same construction as client openAndBootstrap).
func buildBootstrapRecord(t *testing.T, masterKey []byte, endpoint string, proto protocol.Proto, method protocol.Method, target string) (saltB64 string, body []byte) {
	t.Helper()
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	sk, err := crypto.NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)
	// The bootstrap record is always encrypted with AES-256-GCM regardless
	// of the session method negotiated in the handshake frame.
	enc, counter, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	require.NoError(t, err)
	aad := crypto.BuildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	hs := protocol.NewFrameHANDSHAKE(protocol.Handshake{
		Version: protocol.Version3,
		Proto:   proto,
		Method:  method,
		Target:  target,
	})
	plaintext := protocol.EncodeFrames([]protocol.Frame{hs})

	var buf bytes.Buffer
	rw := crypto.NewRecordWriter(&buf, enc, counter, aad)
	require.NoError(t, rw.WriteRecord(plaintext))
	return base64.RawURLEncoding.EncodeToString(salt), buf.Bytes()
}

func newRejectTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newRejectTestClient(t *testing.T) *http.Transport {
	t.Helper()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Protocols:       &http.Protocols{},
	}
	tr.Protocols.SetHTTP2(true)
	t.Cleanup(tr.CloseIdleConnections)
	return tr
}

func postBootstrap(t *testing.T, tr *http.Transport, url, saltB64 string, body io.Reader) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, body)
	require.NoError(t, err)
	req.Header.Set("x-es", saltB64)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	return resp, b
}

func saltToB64(salt []byte) string {
	return base64.RawURLEncoding.EncodeToString(salt)
}

func newRejectHandler(timeout time.Duration) http.Handler {
	return NewProxyHandler(ProxyHandlerConfig{
		MasterKey:         bytes.Repeat([]byte{0x42}, 32),
		AllowedMethods:    []string{protocol.MethodAES256GCM.String()},
		HandshakeTimeout:  timeout,
		Timeout:           5 * time.Second,
		StreamIdleTimeout: 300 * time.Second,
		UDPIdleTimeout:    30 * time.Second,
		BatchWindowMS:     1,
	})
}

// TestServeHTTP_HandshakeTimeout408 verifies that a bootstrap record which
// never completes gets 408 Request Timeout (nginx-style), NOT a camouflaged
// 200 page that would poison the legit client's record stream.
func TestServeHTTP_HandshakeTimeout408(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(150*time.Millisecond))
	tr := newRejectTestClient(t)

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	pr, pw := io.Pipe()
	defer pr.Close()

	resp, body := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP, saltToB64(salt), pr)
	_ = pw.Close()

	require.Equal(t, http.StatusRequestTimeout, resp.StatusCode,
		"timed-out handshake should be answered with 408, body: %s", body)
	require.Empty(t, body)
}

// TestServeHTTP_DecryptFailureKeepsFallback verifies that a keyless request
// (bootstrap decrypt failure) still gets the camouflaged 200 homepage, so
// probing the server is indistinguishable from browsing a normal site.
func TestServeHTTP_DecryptFailureKeepsFallback(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	resp, body := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP,
		saltToB64(salt), bytes.NewReader(bytes.Repeat([]byte{0xAB}, 128)))

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"decrypt failure should keep the 200 fallback page")
	require.True(t, bytes.Contains(body, []byte("<!DOCTYPE html>")),
		"expected fallback HTML body, got: %s", body)
}

// TestServeHTTP_ReplaySalt400 verifies that a replayed salt is rejected with
// 400 after the requester proved key possession.
func TestServeHTTP_ReplaySalt400(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	saltB64 := saltToB64(salt)

	resp1, _ := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP, saltB64,
		bytes.NewReader(bytes.Repeat([]byte{0xAB}, 128)))
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	resp2, body2 := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP, saltB64,
		bytes.NewReader(bytes.Repeat([]byte{0xAB}, 128)))
	require.Equal(t, http.StatusBadRequest, resp2.StatusCode,
		"replayed salt should be rejected with 400, body: %s", body2)
	require.Empty(t, body2)
}

// TestServeHTTP_EndpointMismatch404 verifies that a valid handshake whose
// proto does not match the requested endpoint path is rejected with 404.
func TestServeHTTP_EndpointMismatch404(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	saltB64, body := buildBootstrapRecord(t, masterKey, sharedconfig.EndpointTCP,
		protocol.ProtoUDP, protocol.MethodAES256GCM, "1.1.1.1:53")
	resp, respBody := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP, saltB64, bytes.NewReader(body))
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"endpoint mismatch should be rejected with 404, body: %s", respBody)
}

// TestServeHTTP_MethodNotAllowed405 verifies that a valid handshake using a
// method the server does not allow is rejected with 405.
func TestServeHTTP_MethodNotAllowed405(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	saltB64, body := buildBootstrapRecord(t, masterKey, sharedconfig.EndpointTCP,
		protocol.ProtoTCP, protocol.MethodChaCha20Poly1305, "1.1.1.1:53")
	resp, respBody := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP, saltB64, bytes.NewReader(body))
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode,
		"disallowed method should be rejected with 405, body: %s", respBody)
}

// TestServeHTTP_LANTarget400 verifies that a valid handshake targeting a LAN
// address is rejected with 400 (SSRF guard).
func TestServeHTTP_LANTarget400(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	saltB64, body := buildBootstrapRecord(t, masterKey, sharedconfig.EndpointTCP,
		protocol.ProtoTCP, protocol.MethodAES256GCM, "127.0.0.1:80")
	resp, respBody := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP, saltB64, bytes.NewReader(body))
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"LAN target should be rejected with 400, body: %s", respBody)
}

// TestServeHTTP_ValidHandshakeOctetStream verifies that a valid TCP handshake
// gets the 200 application/octet-stream response (the proxy path commits).
// The target is unreachable, so the relay will fail after the commit — we
// only assert the committed response.
func TestServeHTTP_ValidHandshakeOctetStream(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	saltB64, body := buildBootstrapRecord(t, masterKey, sharedconfig.EndpointTCP,
		protocol.ProtoTCP, protocol.MethodAES256GCM, "203.0.113.1:9")
	resp, _ := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP, saltB64, bytes.NewReader(body))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/octet-stream") {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
}
