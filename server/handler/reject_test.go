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
	"github.com/nange/easyss/v3/shaper"
	"github.com/stretchr/testify/require"
)

// buildBootstrapRecord 生成真实 easyss 客户端会发送的加密 bootstrap 记录
// （与客户端 openAndBootstrap 的构造方式相同）。
func buildBootstrapRecord(t *testing.T, masterKey []byte, endpoint string, proto protocol.Proto, method protocol.Method, target string) (saltB64 string, body []byte) {
	t.Helper()
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	sk, err := crypto.NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)
	hs := protocol.NewFrameHANDSHAKE(protocol.Handshake{
		Version: protocol.Version3,
		Proto:   proto,
		Method:  method,
		Target:  target,
	})
	plaintext := protocol.EncodeFrames([]protocol.Frame{hs})

	// bootstrap 记录始终使用 AES-256-GCM 加密，与握手帧中协商的会话方法无关。
	var buf bytes.Buffer
	rw, err := sk.BootstrapWriter(&buf)
	require.NoError(t, err)
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
	resp.Body.Close() //nolint:errcheck
	return resp, b
}

func saltToB64(salt []byte) string {
	return base64.RawURLEncoding.EncodeToString(salt)
}

func newRejectHandler(handshakeTimeout time.Duration) http.Handler {
	return NewProxyHandler(ProxyHandlerConfig{
		MasterKey:        bytes.Repeat([]byte{0x42}, 32),
		AllowedMethods:   []string{protocol.MethodAES256GCM.String()},
		Timeouts:         sharedconfig.NewTimeouts(5 * time.Second),
		HandshakeTimeout: handshakeTimeout,
		Shaper:           shaper.Config{BatchWindowMS: 1},
	})
}

// TestServeHTTP_HandshakeTimeout408 验证从未完整到达的 bootstrap 记录会得到
// 408 Request Timeout（nginx 风格），而不是会污染合法客户端记录流的伪装 200 页面。
func TestServeHTTP_HandshakeTimeout408(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(150*time.Millisecond))
	tr := newRejectTestClient(t)

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	pr, pw := io.Pipe()
	defer pr.Close() //nolint:errcheck

	resp, body := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP, saltToB64(salt), pr)
	_ = pw.Close()

	require.Equal(t, http.StatusRequestTimeout, resp.StatusCode,
		"timed-out handshake should be answered with 408, body: %s", body)
	require.Empty(t, body)
}

// TestServeHTTP_DecryptFailureKeepsFallback 验证无密钥请求（bootstrap 解密失败）
// 仍会得到伪装成普通站点的 200 首页，使探测服务器与浏览普通网站无法区分。
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

// TestServeHTTP_ReplaySalt400 验证在请求者证明持有密钥之后，重放的 salt 会被 400 拒绝。
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

// TestServeHTTP_EndpointMismatch404 验证 proto 与请求的端点路径不匹配的合法握手会被 404 拒绝。
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

// TestServeHTTP_MethodNotAllowed405 验证使用服务器不允许的方法的合法握手会被 405 拒绝。
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

// TestServeHTTP_LANTarget400 验证以 LAN 地址为目标的合法握手会被 400 拒绝（SSRF 防护）。
func TestServeHTTP_LANTarget400(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	for _, target := range []string{
		"127.0.0.1:80",
		"10.0.0.1:80",
		"100.64.0.1:80",     // CGNAT
		"192.0.2.1:80",      // TEST-NET-1
		"198.18.0.1:80",     // 基准测试网段
		"203.0.113.1:80",    // TEST-NET-3
		"255.255.255.255:9", // 广播地址
	} {
		saltB64, body := buildBootstrapRecord(t, masterKey, sharedconfig.EndpointTCP,
			protocol.ProtoTCP, protocol.MethodAES256GCM, target)
		resp, respBody := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP, saltB64, bytes.NewReader(body))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"non-public target %s should be rejected with 400, body: %s", target, respBody)
	}
}

// TestServeHTTP_ValidHandshakeOctetStream 验证合法的 TCP 握手会得到
// 200 application/octet-stream 响应（代理路径已提交）。
// 目标不可达，因此中继会在提交之后失败 —— 这里只断言已提交的响应。
func TestServeHTTP_ValidHandshakeOctetStream(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	saltB64, body := buildBootstrapRecord(t, masterKey, sharedconfig.EndpointTCP,
		protocol.ProtoTCP, protocol.MethodAES256GCM, "8.8.8.8:9")
	resp, _ := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP, saltB64, bytes.NewReader(body))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/octet-stream") {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
}
