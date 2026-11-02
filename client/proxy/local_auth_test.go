package proxy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/things-go/go-socks5/statute"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
)

// TestIsLoopbackAddr 固定"本机来源"的判据：只有回环地址免认证，私网 LAN 来源必须认证。
func TestIsLoopbackAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:5555", true},
		{"127.0.0.2:5555", true},
		{"[::1]:5555", true},
		{"192.168.1.10:5555", false},
		{"10.0.0.1:5555", false},
		{"[fe80::1%en0]:5555", false},
		{"0.0.0.0:5555", false},
		{"", false},
		{"not-an-address", false},
	}

	for _, tt := range tests {
		if got := isLoopbackAddr(tt.addr); got != tt.want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

// TestSocks5AuthMethodsOrder 钉住方法列表的顺序：库按服务端顺序挑选客户端也声明的方法，
// UserPass 若排在 no-auth 之后，同时声明两种方法的远程客户端会被无鉴权放行。
func TestSocks5AuthMethodsOrder(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		username string
		password string
		wantCode []uint8
	}{
		{"未配置鉴权", "", "", []uint8{statute.MethodNoAuth}},
		{"只配用户名仍算未启用", "user", "", []uint8{statute.MethodNoAuth}},
		{"只配密码仍算未启用", "", "pass", []uint8{statute.MethodNoAuth}},
		{"同时配置", "user", "pass", []uint8{statute.MethodUserPassAuth, statute.MethodNoAuth}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			methods := socks5AuthMethods(tc.username, tc.password)
			if len(methods) != len(tc.wantCode) {
				t.Fatalf("auth methods = %d, want %d", len(methods), len(tc.wantCode))
			}
			for i, want := range tc.wantCode {
				if got := methods[i].GetCode(); got != want {
					t.Errorf("method[%d] = %d, want %d", i, got, want)
				}
			}
		})
	}
}

// TestLoopbackNoAuthAuthenticator 固定 no-auth 分支只接受回环来源：远程来源被拒绝时
// 要回 MethodNoAcceptable，客户端因此看到协议错误而不是连接被静默断开。
func TestLoopbackNoAuthAuthenticator(t *testing.T) {
	t.Parallel()

	auth := loopbackNoAuthAuthenticator{}

	var buf bytes.Buffer
	ctx, err := auth.Authenticate(nil, &buf, "127.0.0.1:5555")
	if err != nil {
		t.Fatalf("loopback Authenticate: %v", err)
	}
	if ctx.Method != statute.MethodNoAuth {
		t.Errorf("loopback method = %d, want %d", ctx.Method, statute.MethodNoAuth)
	}
	if want := []byte{statute.VersionSocks5, statute.MethodNoAuth}; !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("loopback reply = %v, want %v", buf.Bytes(), want)
	}

	buf.Reset()
	if _, err := auth.Authenticate(nil, &buf, "192.168.1.10:5555"); !errors.Is(err, errRemoteNoAuthRejected) {
		t.Fatalf("remote Authenticate error = %v, want errRemoteNoAuthRejected", err)
	}
	if want := []byte{statute.VersionSocks5, statute.MethodNoAcceptable}; !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("remote reply = %v, want %v", buf.Bytes(), want)
	}

	for _, addr := range []string{"", "garbage"} {
		buf.Reset()
		if _, err := auth.Authenticate(nil, &buf, addr); err == nil {
			t.Errorf("Authenticate(%q) succeeded, want rejection", addr)
		}
	}
}

// TestHTTPProxyAuthOK 固定 HTTP 入口的同一判据：回环来源免认证（系统代理、/stats 都
// 不带凭据），非回环来源按配置的用户名密码校验；只配一项等同未启用（与 SOCKS5 一致）。
func TestHTTPProxyAuthOK(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		username  string
		password  string
		remote    string
		withCreds bool
		want      bool
	}{
		{"回环无凭据", "user", "pass", "127.0.0.1:5555", false, true},
		{"回环有凭据", "user", "pass", "[::1]:5555", true, true},
		{"远程无凭据", "user", "pass", "192.168.1.10:5555", false, false},
		{"远程有凭据", "user", "pass", "192.168.1.10:5555", true, true},
		{"远程·只配用户名视为未启用", "user", "", "192.168.1.10:5555", false, true},
		{"远程·只配密码视为未启用", "", "pass", "192.168.1.10:5555", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &HTTPProxyServer{username: tt.username, password: tt.password}
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.RemoteAddr = tt.remote
			if tt.withCreds {
				req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))
			}
			if got := s.authOK(req); got != tt.want {
				t.Errorf("authOK(user=%q, pass=%q, remote=%s, creds=%v) = %v, want %v",
					tt.username, tt.password, tt.remote, tt.withCreds, got, tt.want)
			}
		})
	}
}

// TestHTTPProxySocksURLFollowsAuthPredicate 固定拨本地 SOCKS5 的凭据判据与入口同源：
// 只配一项时入口并未启用鉴权，反代链路的 socks5 URL 也不能带 userinfo。
func TestHTTPProxySocksURLFollowsAuthPredicate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		username string
		password string
		wantUser bool
	}{
		{"未配置", "", "", false},
		{"只配用户名", "user", "", false},
		{"只配密码", "", "pass", false},
		{"同时配置", "user", "pass", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := NewHTTPProxyServer(HTTPProxyOptions{
				ListenAddr: "127.0.0.1:5080",
				SocksAddr:  "127.0.0.1:4080",
				Username:   tc.username,
				Password:   tc.password,
			})
			if err != nil {
				t.Fatalf("NewHTTPProxyServer: %v", err)
			}
			if got := s.socksURL.User != nil; got != tc.wantUser {
				t.Errorf("socksURL.User set = %v, want %v (user=%q pass=%q)",
					got, tc.wantUser, tc.username, tc.password)
			}
		})
	}
}

// TestSocks5LoopbackSkipsAuth 端到端固定协商行为：鉴权开启后，回环客户端只声明 no-auth
// 仍被接受；同时声明两种方法时服务端必须选 UserPass（顺序契约）。
func TestSocks5LoopbackSkipsAuth(t *testing.T) {
	t.Parallel()

	addr := freeLoopbackAddr(t)
	srv, err := NewSocks5Server(Socks5Options{
		ListenAddr: addr,
		Username:   "user",
		Password:   "pass",
		Handler:    newTestStreamHandler(&mockTransport{}),
		Method:     protocol.MethodAES256GCM,
		Timeouts: config.Timeouts{
			Base:       30 * time.Second,
			Dial:       10 * time.Second,
			StreamIdle: 30 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Close() })
	if err := waitListenerUp(addr, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	negotiate := func(methods ...byte) [2]byte {
		t.Helper()

		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() { _ = conn.Close() }()

		if _, err := conn.Write(append([]byte{statute.VersionSocks5, byte(len(methods))}, methods...)); err != nil {
			t.Fatalf("write method request: %v", err)
		}
		reply := make([]byte, 2)
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("read method reply: %v", err)
		}
		return [2]byte{reply[0], reply[1]}
	}

	if got, want := negotiate(statute.MethodNoAuth), [2]byte{statute.VersionSocks5, statute.MethodNoAuth}; got != want {
		t.Errorf("loopback no-auth negotiation = %v, want %v", got, want)
	}
	if got, want := negotiate(statute.MethodNoAuth, statute.MethodUserPassAuth),
		[2]byte{statute.VersionSocks5, statute.MethodUserPassAuth}; got != want {
		t.Errorf("loopback dual-method negotiation = %v, want %v (UserPass must win)", got, want)
	}
}
