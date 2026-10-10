package handler

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
)

// TestLocalDERPMatches 固定"目标就是本服务端自己的内嵌 DERP"的判定：host 不区分
// 大小写、端口按数值比较，任何其它组合都必须落回普通路径（那条路径带着完整的
// SSRF 判定，因此这里的宽严直接决定回环拨号特例的边界）。
func TestLocalDERPMatches(t *testing.T) {
	l := &localDERP{match: "derp.example.com:443", loopback: "127.0.0.1:8443"}

	cases := []struct {
		name   string
		target string
		want   bool
	}{
		{"完全一致", "derp.example.com:443", true},
		{"host 大小写不敏感", "DERP.Example.COM:443", true},
		{"端口按数值比较", "derp.example.com:0443", true},
		{"别的端口", "derp.example.com:444", false},
		{"别的主机", "example.com:443", false},
		{"子域不算", "x.derp.example.com:443", false},
		{"缺端口", "derp.example.com", false},
		{"空目标", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := l.matches(tc.target); got != tc.want {
				t.Errorf("matches(%q) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}

	t.Run("未配置时一律不匹配", func(t *testing.T) {
		var nilLocal *localDERP
		if nilLocal.matches("derp.example.com:443") {
			t.Error("a nil localDERP must not match anything")
		}
		empty := &localDERP{}
		if empty.matches("derp.example.com:443") {
			t.Error("an unconfigured localDERP must not match anything")
		}
	})
}

// TestServeHTTP_LocalDERPDialsTheLoopbackListener 是 DERP 私有化的服务端一侧
// 端到端断言：握手目标等于本服务端自己通告的 DERP 地址时，这条流被改拨到本机
// 回环监听，而不是去解析并连接自己的公网地址（后者只会拿到伪装页面）。
//
// 断言落在"回环监听器真的收到了一条连接"上：这是从外部可观测、且无法由伪装
// 页面或 4xx 伪造的事实。
func TestServeHTTP_LocalDERPDialsTheLoopbackListener(t *testing.T) {
	const (
		masterKey = "0123456789abcdef0123456789abcdef"
		derpAddr  = "derp.example.com:443"
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		_ = conn.Close()
	}()

	// 解析入口被打桩成"解析必然失败"：命中特例的流根本不该调用它，一旦调用就
	// 说明它走的是普通路径（那条路径会拒绝回环目标）。
	calls := stubResolveHost(t, nil, errNoResolve)

	h := NewProxyHandler(ProxyHandlerConfig{
		MasterKey:         []byte(masterKey),
		AllowedMethods:    []string{protocol.MethodAES256GCM.String()},
		Timeouts:          sharedconfig.NewTimeouts(5 * time.Second),
		Shaper:            shaper.Config{BatchWindowMS: 1},
		LocalDERPAddr:     derpAddr,
		LocalDERPLoopback: ln.Addr().String(),
	})
	srv := newRejectTestServer(t, h)
	tr := newRejectTestClient(t)

	salt, body := buildBootstrapRecord(t, []byte(masterKey), sharedconfig.EndpointTCP,
		protocol.ProtoTCP, protocol.MethodAES256GCM, derpAddr)
	resp, _ := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP, salt, bytes.NewReader(body))
	defer resp.Body.Close() //nolint:errcheck

	// 会话已经开始：octet-stream 头已经写出（此后这条流由 TCP handler 接管）。
	require.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the loopback DERP listener never received a connection")
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("the target was resolved %d times: a local DERP target must go straight to loopback", got)
	}
}

// TestServeHTTP_LocalDERPDoesNotWidenTargets 是上一条的阴性对照：只有**完全等于**
// 本服务端 DERP 地址的目标才享受回环特例。别的目标必须回到普通路径——那里有完整
// 的 SSRF 判定，因此"解析到 LAN"依旧被拒。
func TestServeHTTP_LocalDERPDoesNotWidenTargets(t *testing.T) {
	const masterKey = "0123456789abcdef0123456789abcdef"

	stubResolveHost(t, []string{"10.1.2.3"}, nil)

	h := NewProxyHandler(ProxyHandlerConfig{
		MasterKey:         []byte(masterKey),
		AllowedMethods:    []string{protocol.MethodAES256GCM.String()},
		Timeouts:          sharedconfig.NewTimeouts(5 * time.Second),
		Shaper:            shaper.Config{BatchWindowMS: 1},
		LocalDERPAddr:     "derp.example.com:443",
		LocalDERPLoopback: "127.0.0.1:8443",
	})
	srv := newRejectTestServer(t, h)
	tr := newRejectTestClient(t)

	for _, target := range []string{"derp.example.com:444", "example.com:443", "127.0.0.1:8443"} {
		t.Run(target, func(t *testing.T) {
			salt, body := buildBootstrapRecord(t, []byte(masterKey), sharedconfig.EndpointTCP,
				protocol.ProtoTCP, protocol.MethodAES256GCM, target)
			resp, _ := postBootstrap(t, tr, srv.URL+sharedconfig.EndpointTCP, salt, bytes.NewReader(body))
			defer resp.Body.Close() //nolint:errcheck

			require.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"a target that is not this server's own DERP address must keep the SSRF check")
		})
	}
}

// errNoResolve 让被打桩的解析入口明确失败：命中回环特例的流不该解析任何东西。
var errNoResolve = errors.New("resolution is not expected on this path")
