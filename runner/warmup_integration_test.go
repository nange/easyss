package runner

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/config"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/transport"
	"github.com/nange/easyss/v3/util"
)

// startProbeServer 启动一个支持 HTTP/2 的本地 TLS 服务器，以真实服务器预生成的
// 载荷响应 /v3/probe，模拟 transport/http2 确认连接已预热的方式
// （200 + octet-stream + 精确的载荷大小）。它返回服务器 URL 和服务器自签名
// 证书的 PEM 路径，以便客户端在没有任何真实网络的情况下指向它。
func startProbeServer(t *testing.T) (srvURL, caPath string, probes *atomic.Int64) {
	t.Helper()

	probes = &atomic.Int64{}
	payload := make([]byte, sharedconfig.ProbePayloadSize)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != sharedconfig.EndpointProbe {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		probes.Add(1)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.Config.Protocols = &http.Protocols{}
	srv.Config.Protocols.SetHTTP2(true)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	caPath = filepath.Join(t.TempDir(), "ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("write test CA: %v", err)
	}

	return srv.URL, caPath, probes
}

// warmUpConfig 将客户端配置指向本地探测服务器，预热保持默认值（启用）。
func warmUpConfig(t *testing.T, srvURL, caPath string) *config.ClientConfig {
	t.Helper()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srvURL, "https://"))
	if err != nil {
		t.Fatalf("parse test server URL %q: %v", srvURL, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse test server port %q: %v", portStr, err)
	}
	if !util.IsIP(host) {
		// 字面 IP 使测试不涉及 resolveServerDomain：它会跳过字面 IP，
		// 因此不会发出真实的 DNS 查询。
		t.Fatalf("test server host %q is not an IP", host)
	}

	cfg := testConfig()
	cfg.Servers[0].Address = host
	cfg.Servers[0].Port = port
	cfg.Servers[0].CAPath = caPath
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = 0
	cfg.Routing.IPV6Rule = "disable"
	return cfg
}

// TestRunWarmsUpOverRealTransport 是对 runner 所拥有的预热逻辑的端到端检查：
// 在默认配置下，核心启动后必须通过其真实的 HTTP/2 传输层探测两个调度池。
func TestRunWarmsUpOverRealTransport(t *testing.T) {
	srvURL, caPath, probes := startProbeServer(t)
	cfg := warmUpConfig(t, srvURL, caPath)

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(core.Stop)

	// 两个池（priority + bulk）都被预热，各自使用一次探测。
	deadline := time.Now().Add(sharedconfig.WarmUpStartDelay + sharedconfig.WarmUpTimeout + time.Second)
	for time.Now().Before(deadline) && probes.Load() < 2 {
		time.Sleep(10 * time.Millisecond)
	}

	if got := probes.Load(); got < 2 {
		t.Fatalf("got %d probe requests, want 2 (one per scheduling pool)", got)
	}
}

// TestRunDoesNotWaitForWarmUp 固定预热的非阻塞约定：Run 在预热探测仍被阻塞时
// 就返回，因此桌面端启动和 gomobile 绑定都不会为预热买单。探测会一直阻塞
// 直到测试释放它，因此任何调度假设（延迟与超时竞争）都不会让本测试偶然
// 通过或失败。
func TestRunDoesNotWaitForWarmUp(t *testing.T) {
	shortWarmUpStartDelay(t, 0)

	old := warmUpCore
	release := make(chan struct{})
	finished := make(chan struct{})
	warmUpCore = func(transport.Transport, time.Duration) error {
		defer close(finished)
		<-release
		return nil
	}
	// 与桩测试不同，这个桩只在预热 goroutine 上运行，且不触碰 *testing.T，
	// 因此在清理中释放它是安全的。
	t.Cleanup(func() {
		warmUpCore = old
		close(release)
	})

	cfg := testConfig()
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = 0

	type result struct {
		core *Core
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		core, err := Run(cfg)
		resultCh <- result{core: core, err: err}
	}()

	var res result
	select {
	case res = <-resultCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run blocked on the warm-up instead of dispatching it in the background")
	}

	// Run 返回时探测仍处于停滞状态：这正是约定。
	select {
	case <-finished:
		t.Fatal("the warm-up probe finished before Run returned, so Run waited for it")
	default:
	}

	if res.err != nil {
		t.Fatalf("Run: %v", res.err)
	}
	res.core.Stop()
}

// TestRunDoesNotWarmUpWhenDisabled 验证配置开关：设置 transport.disable_warm_up
// 后，核心绝不会探测服务器。
func TestRunDoesNotWarmUpWhenDisabled(t *testing.T) {
	srvURL, caPath, probes := startProbeServer(t)
	cfg := warmUpConfig(t, srvURL, caPath)
	cfg.Transport.DisableWarmUp = true

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(core.Stop)

	// 等待超过预热本应发起探测的时刻。
	time.Sleep(sharedconfig.WarmUpStartDelay + 300*time.Millisecond)

	if got := probes.Load(); got != 0 {
		t.Fatalf("got %d probe requests with the warm-up disabled, want 0", got)
	}
}

// TestRunWarmUpSkippedWithoutSocksServer 验证 socks_port = 0 的情况：
// 没有本地 SOCKS5 代理可供预热，因此核心跳过预热，而不是失败或仍然探测。
func TestRunWarmUpSkippedWithoutSocksServer(t *testing.T) {
	srvURL, caPath, probes := startProbeServer(t)
	cfg := warmUpConfig(t, srvURL, caPath)
	cfg.Local.SocksPort = 0
	cfg.Local.HTTPPort = 0

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(core.Stop)

	time.Sleep(sharedconfig.WarmUpStartDelay + 200*time.Millisecond)

	if got := probes.Load(); got != 0 {
		t.Fatalf("got %d probe requests without a SOCKS5 server, want 0", got)
	}
}
