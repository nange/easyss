package vpn

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"

	"github.com/nange/easyss/v3/config"
)

// TestNewDERPServer 固定构造、公钥稳定与重复 Close（Shutdown 与会话切换可能各调一次）。
func TestNewDERPServer(t *testing.T) {
	priv := key.NewNode()
	srv := NewDERPServer(priv, 0)
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

// TestDERPServerHandlerIsMountable 固定处理器可挂到分流器上，探测路径仍由 derpserver 回答。
func TestDERPServerHandlerIsMountable(t *testing.T) {
	srv := NewDERPServer(key.NewNode(), 0)
	defer func() { _ = srv.Close() }()

	fallback := &stubFallback{}
	h := NewDERPMount(srv.Handler(), fallback)

	req := httptest.NewRequest(http.MethodGet, "/derp/probe", nil)
	req.RemoteAddr = "127.0.0.1:51234"
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

// TestDERPServerNilClose 固定空值安全：会话切换可能在从未启用 VPN 时调 Close。
func TestDERPServerNilClose(t *testing.T) {
	var srv *DERPServer
	if err := srv.Close(); err != nil {
		t.Errorf("(*DERPServer)(nil).Close() = %v, want nil", err)
	}
}

// TestDERPServerUpgradeOverTLS 用与 derphttp 相同的握手打真实 TLS 监听：固定 NewDERPMount
// 放行、TLS 下 Hijack 可用，以及响应来自本进程中继（Derp-Public-Key、不是伪装页）。
func TestDERPServerUpgradeOverTLS(t *testing.T) {
	priv := key.NewNode()
	srv := NewDERPServer(priv, 0)
	defer func() { _ = srv.Close() }()

	fallback := &stubFallback{}
	ts := httptest.NewTLSServer(NewDERPMount(srv.Handler(), fallback))
	defer ts.Close()

	conn, err := tls.Dial("tcp", ts.Listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// 与 derphttp 的握手请求逐字一致（derphttp_client.go 的 connect）。
	host := ts.Listener.Addr().String()
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
		config.DefaultVPNDERPPath, host); err != nil {
		t.Fatalf("write request: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+host+config.DefaultVPNDERPPath, nil)
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

// TestDERPServerAppliesSendQueueDepth 固定归一化后的深度在 derpserver.New 那一刻确实进了进程
// 环境，且构造后还原：运维预先设置的同名值既不生效也不被改动。
func TestDERPServerAppliesSendQueueDepth(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"未配置取共享默认值", 0, config.DefaultDERPSendQueueDepth},
		{"负值视为未配置", -7, config.DefaultDERPSendQueueDepth},
		{"显式配置原样落位", 256, 256},
		{"越界钳到下界", 1, config.MinDERPSendQueueDepth},
		{"越界钳到上界", 1 << 20, config.MaxDERPSendQueueDepth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const operatorValue = "777"
			t.Setenv(derpSendQueueDepthEnv, operatorValue)

			orig := newDERPServer
			seen := make(chan string, 1)
			newDERPServer = func(k key.NodePrivate, logf logger.Logf) *derpserver.Server {
				seen <- os.Getenv(derpSendQueueDepthEnv)
				return orig(k, logf)
			}
			t.Cleanup(func() { newDERPServer = orig })

			srv := NewDERPServer(key.NewNode(), tc.in)
			defer func() { _ = srv.Close() }()

			select {
			case got := <-seen:
				if got != strconv.Itoa(tc.want) {
					t.Errorf("the depth visible to derpserver.New = %q, want %q", got, strconv.Itoa(tc.want))
				}
			case <-time.After(5 * time.Second):
				t.Fatal("derpserver.New was never called")
			}
			if got := srv.SendQueueDepth(); got != tc.want {
				t.Errorf("SendQueueDepth() = %d, want %d", got, tc.want)
			}
			if got := os.Getenv(derpSendQueueDepthEnv); got != operatorValue {
				t.Errorf("%s = %q after construction, want the pre-existing %q left untouched",
					derpSendQueueDepthEnv, got, operatorValue)
			}
		})
	}
}

// TestDERPServerLeavesNoEnvironmentVariableBehind 固定构造后不残留该环境变量。
func TestDERPServerLeavesNoEnvironmentVariableBehind(t *testing.T) {
	orig, had := os.LookupEnv(derpSendQueueDepthEnv)
	if err := os.Unsetenv(derpSendQueueDepthEnv); err != nil {
		t.Fatalf("Unsetenv: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(derpSendQueueDepthEnv, orig)
			return
		}
		_ = os.Unsetenv(derpSendQueueDepthEnv)
	})

	srv := NewDERPServer(key.NewNode(), 256)
	defer func() { _ = srv.Close() }()

	if got, ok := os.LookupEnv(derpSendQueueDepthEnv); ok {
		t.Errorf("%s = %q after construction: the depth must be an implementation detail, not a process-wide setting",
			derpSendQueueDepthEnv, got)
	}
}
