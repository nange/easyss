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

	sharedconfig "github.com/nange/easyss/v3/config"
)

// TestNewDERPServer 固定内嵌中继的最小契约：能构造、能给出稳定的公钥、能重复
// 关闭（服务端 Shutdown 与会话切换都可能各自调一次）。
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

// TestDERPServerHandlerIsMountable 固定中继处理器能被挂到我们的分流器上，且
// 不带 Upgrade 的探测路径仍然由 derpserver 自己回答（探测端点必须保持可用）。
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
	srv := NewDERPServer(priv, 0)
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

// TestDERPServerAppliesSendQueueDepth 固定"配置值确实被交给了 derpserver"。
//
// 深度只能经进程环境落位（fork 在 derpserver.New 里读一次那个开关，没有构造参数），
// 因此这条测试用 newDERPServer 注入点在**构造那一刻**读一次环境：那正是 fork 看到的
// 值。同时钉住两件事：归一化后的值落位、以及构造之后进程环境被还原——进程环境里预先
// 存在的同名值既不生效（配置是唯一旋钮），也不会被我们改动。
func TestDERPServerAppliesSendQueueDepth(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"未配置取共享默认值", 0, sharedconfig.DefaultDERPSendQueueDepth},
		{"负值视为未配置", -7, sharedconfig.DefaultDERPSendQueueDepth},
		{"显式配置原样落位", 256, 256},
		{"越界钳到下界", 1, sharedconfig.MinDERPSendQueueDepth},
		{"越界钳到上界", 1 << 20, sharedconfig.MaxDERPSendQueueDepth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 模拟"运维自己在进程环境里设过这个变量"：它既不该生效，也不该被改动。
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

// TestDERPServerLeavesNoEnvironmentVariableBehind 是上一条的另一半：进程环境里本来
// 没有这个变量时，构造之后也不该留下它——留下会让人以为那是一个受支持的配置入口。
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
