package vpn

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/types/key"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// TestNewDERPServer 固定内嵌中继的最小契约：能构造、能给出稳定的公钥、能重复
// 关闭（服务端 Shutdown 与会话切换都可能各自调一次）。
func TestNewDERPServer(t *testing.T) {
	priv := key.NewNode()
	srv := NewDERPServer(priv)
	if srv == nil {
		t.Fatal("NewDERPServer returned nil")
	}
	if got, want := srv.PublicKey(), priv.Public(); got != want {
		t.Errorf("PublicKey() = %v, want %v", got, want)
	}
	if srv.Handler() == nil {
		t.Fatal("Handler() is nil")
	}
	if err := srv.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestDERPServerHandlerIsMountable 固定中继处理器能被挂到我们的分流器上，且
// 不带 Upgrade 的探测路径仍然由 derpserver 自己回答（探测端点必须保持可用）。
func TestDERPServerHandlerIsMountable(t *testing.T) {
	srv := NewDERPServer(key.NewNode())
	defer func() { _ = srv.Close() }()

	fallback := &stubFallback{}
	h := NewDERPMount(srv.Handler(), fallback)

	req := httptest.NewRequest(http.MethodGet, "/derp/probe", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /derp/probe status = %d, want 200", rec.Code)
	}
	if fallback.calls != 0 {
		t.Errorf("fallback calls = %d, want 0 for a probe request", fallback.calls)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want * (derpserver's ProbeHandler response)", got)
	}
}

// TestDERPServerNilClose 守护空值安全：会话切换路径可能在从未启用 VPN 的情况下
// 调用 Close。
func TestDERPServerNilClose(t *testing.T) {
	var srv *DERPServer
	if err := srv.Close(); err != nil {
		t.Errorf("(*DERPServer)(nil).Close() = %v, want nil", err)
	}
}

// TestDERPServerUpgradeOverTLS 是本阶段最强的一条证据：把内嵌中继挂到真实
// 的 TLS HTTP 服务器上，再用**与 derphttp 完全相同**的最小握手请求（GET /derp +
// Upgrade: DERP）打一次，期望拿到 101 与 Derp-Public-Key。
//
// 它同时覆盖了三件事：vpn.NewDERPMount 会把真实 DERP 请求放行、http.Server 的
// Hijack 路径在我们的 TLS 配置下可用、以及中继确实由我们自己的进程提供（而不是
// 回落到伪装页）。
func TestDERPServerUpgradeOverTLS(t *testing.T) {
	priv := key.NewNode()
	srv := NewDERPServer(priv)
	defer func() { _ = srv.Close() }()

	fallback := &stubFallback{}
	ts := httptest.NewTLSServer(NewDERPMount(srv.Handler(), fallback))
	defer ts.Close()

	conn, err := tls.Dial("tcp", ts.Listener.Addr().String(), &tls.Config{
		// 测试服务器用的是自签证书；DERP 客户端在 InsecureForTests 下同样跳过校验。
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// 逐字照抄 derphttp 的握手请求（derphttp_client.go 的 connect）。
	host := ts.Listener.Addr().String()
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
		sharedconfig.DefaultVPNDERPPath, host); err != nil {
		t.Fatalf("write request: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+host+sharedconfig.DefaultVPNDERPPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101 (headers %v)", resp.StatusCode, resp.Header)
	}
	if got := resp.Header.Get("Derp-Public-Key"); got != priv.Public().UntypedHexString() {
		t.Errorf("Derp-Public-Key = %q, want %q", got, priv.Public().UntypedHexString())
	}
	if fallback.calls != 0 {
		t.Errorf("fallback calls = %d, want 0 for a real DERP upgrade", fallback.calls)
	}
}
