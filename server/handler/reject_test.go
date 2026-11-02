package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
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
	return newRejectHandlerWith(defaultOutboundDeps(), handshakeTimeout)
}

// newStubbedDeps 让合法握手不依赖真实网络：目标解析成公网地址，拨号立刻失败。重放判定
// 发生在拨号之前，因此两个分支的差异只来自状态机本身。
func newStubbedDeps() *outboundDeps {
	deps := defaultOutboundDeps()
	deps.resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	deps.attempt = func(*net.Dialer, context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	return deps
}

func newRejectHandlerWith(deps *outboundDeps, handshakeTimeout time.Duration) http.Handler {
	return newProxyHandlerWithDeps(ProxyHandlerConfig{
		MasterKey:        bytes.Repeat([]byte{0x42}, 32),
		AllowedMethods:   []string{protocol.MethodAES256GCM.String()},
		Timeouts:         config.NewTimeouts(5 * time.Second),
		HandshakeTimeout: handshakeTimeout,
		Shaper:           shaper.Config{BatchWindowMS: 1},
	}, deps)
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

	resp, body := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltToB64(salt), pr)
	_ = pw.Close()

	require.Equal(t, http.StatusRequestTimeout, resp.StatusCode,
		"timed-out handshake should be answered with 408, body: %s", body)
	require.Equal(t, "nginx", resp.Header.Get("Server"), "reject responses must carry the nginx Server header")
	require.Equal(t, "text/html", resp.Header.Get("Content-Type"))
	require.Contains(t, string(body), "408 Request Time-out", "expected the nginx error page, got: %s", body)
}

// TestServeHTTP_DecryptFailureKeepsFallback 验证无密钥请求（bootstrap 解密失败）
// 仍会得到伪装成普通站点的 200 首页，使探测服务器与浏览普通网站无法区分。
func TestServeHTTP_DecryptFailureKeepsFallback(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	resp, body := postBootstrap(t, tr, srv.URL+config.EndpointTCP,
		saltToB64(salt), bytes.NewReader(bytes.Repeat([]byte{0xAB}, 128)))

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"decrypt failure should keep the 200 fallback page")
	require.True(t, bytes.Contains(body, []byte("<!DOCTYPE html>")),
		"expected fallback HTML body, got: %s", body)
}

// TestServeHTTP_ReplaySaltIsRejected 验证重放的 salt 不会被接受，但响应降级成与"没有密钥"
// 相同的回退页：可区分的状态码（第二次 400）本身就是两个请求就能完成的探测特征。这里用真实
// 握手区分两条分支：第一次 octet-stream，第二次 HTML。
func TestServeHTTP_ReplaySaltIsRejected(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandlerWith(newStubbedDeps(), time.Second))
	tr := newRejectTestClient(t)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	saltB64, body := buildBootstrapRecord(t, masterKey, config.EndpointTCP,
		protocol.ProtoTCP, protocol.MethodAES256GCM, "example.com:443")

	resp1, _ := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltB64, bytes.NewReader(body))
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	require.Equal(t, "application/octet-stream", resp1.Header.Get("Content-Type"))

	resp2, body2 := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltB64, bytes.NewReader(body))
	require.Equal(t, http.StatusOK, resp2.StatusCode,
		"a replayed salt must not answer differently from a request without the key")
	require.True(t, bytes.Contains(body2, []byte("<!DOCTYPE html>")),
		"expected the fallback page, got: %s", body2)
}

// TestServeHTTP_StalledBodyThenReplayIsIndistinguishable 固定 salt 记录的写入时机：只等到 408 的
// 请求没有证明持有密钥，不能留下 salt 记录，否则同一请求的第二次会变成回退页，两个请求即可识别。
func TestServeHTTP_StalledBodyThenReplayIsIndistinguishable(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(150*time.Millisecond))
	tr := newRejectTestClient(t)

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	stalled := func() (int, []byte) {
		// 声明了请求体却不写任何字节：服务端只能等到握手超时。
		pr, pw := io.Pipe()
		defer pr.Close() //nolint:errcheck
		resp, body := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltToB64(salt), pr)
		_ = pw.Close()
		return resp.StatusCode, body
	}

	firstCode, firstBody := stalled()
	secondCode, secondBody := stalled()

	require.Equal(t, http.StatusRequestTimeout, firstCode)
	require.Equal(t, firstCode, secondCode,
		"a timed-out request must not leave a salt record: replaying it would turn 408 into the fallback page")
	require.Equal(t, firstBody, secondBody)
}

// nonCanonicalSalt 返回同一 salt 的另一种写法：16 字节 salt 编码成 22 个字符，最后一个
// 字符只有 2 位有效，另外 4 位取任意值都解码出同样的 16 字节。
func nonCanonicalSalt(t *testing.T, saltB64 string) string {
	t.Helper()
	want, err := base64.RawURLEncoding.DecodeString(saltB64)
	require.NoError(t, err)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	head := saltB64[:len(saltB64)-1]
	for _, c := range alphabet {
		cand := head + string(c)
		if cand == saltB64 {
			continue
		}
		if got, err := base64.RawURLEncoding.DecodeString(cand); err == nil && bytes.Equal(got, want) {
			return cand
		}
	}
	t.Fatalf("no non-canonical encoding found for %q", saltB64)
	return ""
}

// TestServeHTTP_ReplaySaltNonCanonicalRejected 验证重放判定以解码后的 salt 为准：同一 salt 换
// 一种写法仍是重放，否则一条被捕获的握手可被重放多次，复用同一套会话密钥与 nonce。
func TestServeHTTP_ReplaySaltNonCanonicalRejected(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandlerWith(newStubbedDeps(), time.Second))
	tr := newRejectTestClient(t)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	saltB64, body := buildBootstrapRecord(t, masterKey, config.EndpointTCP,
		protocol.ProtoTCP, protocol.MethodAES256GCM, "example.com:443")

	resp1, _ := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltB64, bytes.NewReader(body))
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	require.Equal(t, "application/octet-stream", resp1.Header.Get("Content-Type"))

	resp2, body2 := postBootstrap(t, tr, srv.URL+config.EndpointTCP,
		nonCanonicalSalt(t, saltB64), bytes.NewReader(body))
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	require.True(t, bytes.Contains(body2, []byte("<!DOCTYPE html>")),
		"the same salt in another encoding must be rejected as a replay, got: %s", body2)
}

// TestServeHTTP_RepeatedNoKeyRequestIsIndistinguishable 固定 M-4 的核心结论：同一请求连发两次
// 必须得到逐字节相同的响应，任何状态码/响应头差异都足以在两个请求内识别服务端实现。
func TestServeHTTP_RepeatedNoKeyRequestIsIndistinguishable(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	saltB64 := saltToB64(salt)
	payload := bytes.Repeat([]byte{0xAB}, 128)

	resp1, body1 := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltB64, bytes.NewReader(payload))
	resp2, body2 := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltB64, bytes.NewReader(payload))

	require.Equal(t, http.StatusOK, resp1.StatusCode)
	require.Equal(t, resp1.StatusCode, resp2.StatusCode)
	require.Equal(t, resp1.Header.Get("Content-Type"), resp2.Header.Get("Content-Type"))
	require.Equal(t, resp1.Header.Get("ETag"), resp2.Header.Get("ETag"))
	require.Equal(t, resp1.Header.Get("Content-Length"), resp2.Header.Get("Content-Length"))
	require.Equal(t, body1, body2)
}

// TestServeHTTP_EndpointMismatch404 验证 proto 与请求的端点路径不匹配的合法握手会被 404 拒绝。
func TestServeHTTP_EndpointMismatch404(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	saltB64, body := buildBootstrapRecord(t, masterKey, config.EndpointTCP,
		protocol.ProtoUDP, protocol.MethodAES256GCM, "1.1.1.1:53")
	resp, respBody := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltB64, bytes.NewReader(body))
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"endpoint mismatch should be rejected with 404, body: %s", respBody)
}

// TestServeHTTP_MethodNotAllowed405 验证使用服务器不允许的方法的合法握手会被 405 拒绝。
func TestServeHTTP_MethodNotAllowed405(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	saltB64, body := buildBootstrapRecord(t, masterKey, config.EndpointTCP,
		protocol.ProtoTCP, protocol.MethodChaCha20Poly1305, "1.1.1.1:53")
	resp, respBody := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltB64, bytes.NewReader(body))
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
		saltB64, body := buildBootstrapRecord(t, masterKey, config.EndpointTCP,
			protocol.ProtoTCP, protocol.MethodAES256GCM, target)
		resp, respBody := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltB64, bytes.NewReader(body))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"non-public target %s should be rejected with 400, body: %s", target, respBody)
	}
}

// TestServeHTTP_DomainResolvingToLAN400 验证解析到 LAN 的域名同样在握手阶段被
// 400 拒绝（DNS-rebinding 的检查侧）；解析入口被替换，因此不依赖真实 DNS。
func TestServeHTTP_DomainResolvingToLAN400(t *testing.T) {
	_, d := stubResolveHost(t, []string{"127.0.0.1"}, nil)
	srv := newRejectTestServer(t, newRejectHandlerWith(d.deps, time.Second))
	tr := newRejectTestClient(t)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	saltB64, body := buildBootstrapRecord(t, masterKey, config.EndpointTCP,
		protocol.ProtoTCP, protocol.MethodAES256GCM, "rebind.example.com:80")
	resp, respBody := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltB64, bytes.NewReader(body))
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a domain resolving to LAN should be rejected with 400, body: %s", respBody)
}

// TestServeHTTP_ValidHandshakeOctetStream 验证合法的 TCP 握手会得到
// 200 application/octet-stream 响应（代理路径已提交）。
// 目标不可达，因此中继会在提交之后失败 —— 这里只断言已提交的响应。
func TestServeHTTP_ValidHandshakeOctetStream(t *testing.T) {
	srv := newRejectTestServer(t, newRejectHandler(time.Second))
	tr := newRejectTestClient(t)

	masterKey := bytes.Repeat([]byte{0x42}, 32)
	saltB64, body := buildBootstrapRecord(t, masterKey, config.EndpointTCP,
		protocol.ProtoTCP, protocol.MethodAES256GCM, "8.8.8.8:9")
	resp, _ := postBootstrap(t, tr, srv.URL+config.EndpointTCP, saltB64, bytes.NewReader(body))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/octet-stream") {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
}
