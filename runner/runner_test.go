package runner

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/proxy"
)

func testConfig() *config.ClientConfig {
	cfg := config.DefaultConfig()
	cfg.Servers = []*config.ServerProfile{{
		// 使用字面 IP 让测试不涉及启动阶段的 DNS 工作：
		// resolveServerDomain（以及 client.New 中的 IPv6 解析）都会跳过
		// 字面 IP，因此测试永远不会发起真实的 DNS 查询。
		Address:  "127.0.0.1",
		Port:     443,
		Password: "test-password",
		Method:   "aes-256-gcm",
		Default:  true,
	}}
	// 跳过客户端初始化期间通过直连 DNS 服务器进行的 IPv6 解析，
	// 否则测试中每次查询都会阻塞数秒。
	cfg.Routing.IPV6Rule = "disable"
	return cfg
}

// TestStopImmediatelyAfterRun 防止 Socks5Server.Close 与 Start goroutine 的
// accept 循环初始化竞争时发生的死锁。GOMAXPROCS(1) 强制主 goroutine 先运行到
// Shutdown 的位置，然后服务器 goroutine 才建立 accept 循环，从而确定性地
// 暴露该竞争。Run 之后必须能立即安全地 Stop。
func TestStopImmediatelyAfterRun(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)

	for i := range 5 {
		cfg := testConfig()
		cfg.Local.SocksPort = freePort(t)
		cfg.Local.HTTPPort = 0

		core, err := Run(cfg)
		if err != nil {
			t.Fatalf("Run #%d: %v", i, err)
		}
		core.Stop()
	}
}

// occupyTCPPort 返回一个绑定到随机 127.0.0.1 端口的监听器，它在整个测试期间
// 保持打开，因此该端口不可用。
func occupyTCPPort(t *testing.T) (net.Listener, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() }) //nolint:errcheck
	return l, l.Addr().(*net.TCPAddr).Port
}

// freePort 返回一个当前可用于绑定的端口。
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() //nolint:errcheck
	return port
}

// occupyUDPPort 返回一个绑定到随机 127.0.0.1 UDP 端口的包连接，
// 它在整个测试期间保持打开。
func occupyUDPPort(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	t.Cleanup(func() { pc.Close() }) //nolint:errcheck
	return pc
}

func TestRunFailsFastOnSocksPortConflict(t *testing.T) {
	_, port := occupyTCPPort(t)
	cfg := testConfig()
	cfg.Local.SocksPort = port
	cfg.Local.HTTPPort = 0

	core, err := Run(cfg)
	if err == nil {
		core.Stop()
		t.Fatal("expected error when socks port is occupied")
	}
	if !strings.Contains(err.Error(), "socks5 server listen") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunFailsFastOnHTTPPortConflict(t *testing.T) {
	_, httpPort := occupyTCPPort(t)
	cfg := testConfig()
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = httpPort

	core, err := Run(cfg)
	if err == nil {
		core.Stop()
		t.Fatal("expected error when http port is occupied")
	}
	if !strings.Contains(err.Error(), "http proxy server listen") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrebindUDP(t *testing.T) {
	pc := occupyUDPPort(t)
	if err := prebindUDP(pc.LocalAddr().String()); err == nil {
		t.Fatal("expected error when udp port is occupied")
	}

	freePc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	freeAddr := freePc.LocalAddr().String()
	freePc.Close() //nolint:errcheck

	if err := prebindUDP(freeAddr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunOKWhenPortsAreFree(t *testing.T) {
	cfg := testConfig()
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = freePort(t)

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if core == nil {
		t.Fatal("core is nil")
	}
	core.Stop()
}

// stubWarmUp 替换 warmUpCore，使调度逻辑可以在没有任何网络的情况下被断言。
// 它统计探测次数，在桩探测返回时释放 done，并在测试结束时恢复之前的实现。
//
// startWarmUp 在派发时捕获 warmUpCore，因此比其测试存活得更久的探测即使在
// 下面的清理恢复了包变量之后，仍会调用这个桩。
func stubWarmUp(t *testing.T, err error) (*atomic.Int64, *waitSignal) {
	t.Helper()

	old := warmUpCore
	calls := &atomic.Int64{}
	done := &waitSignal{done: make(chan struct{})}

	warmUpCore = func(*proxy.Socks5Server, time.Duration) error {
		calls.Add(1)
		done.close()
		return err
	}
	t.Cleanup(func() { warmUpCore = old })

	return calls, done
}

// waitSignal 用于报告桩探测已返回。它由桩 goroutine 关闭，
// 并且可以安全地关闭多次。
type waitSignal struct {
	once sync.Once
	done chan struct{}
}

func (w *waitSignal) close() {
	w.once.Do(func() { close(w.done) })
}

// waitProbe 阻塞直到桩探测返回，如果始终未返回则使测试失败。
func (w *waitSignal) waitProbe(t *testing.T, what string) {
	t.Helper()

	select {
	case <-w.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// shortWarmUpStartDelay 缩短后台预热等待的延迟，
// 使测试不必真的睡眠 config.WarmUpStartDelay 那么久。
func shortWarmUpStartDelay(t *testing.T, d time.Duration) {
	t.Helper()

	old := warmUpStartDelay
	warmUpStartDelay = d
	t.Cleanup(func() { warmUpStartDelay = old })
}

// TestStartWarmUpDispatch 覆盖后台预热的门控逻辑：它只在配置允许时运行，
// 且绝不会传播其失败。所有断言都是基于事件的（桩会发出完成信号），
// 因此测试不依赖调度延迟——而调度延迟会被竞态检测器放大。
func TestStartWarmUpDispatch(t *testing.T) {
	tests := []struct {
		name       string
		disable    bool
		nilServer  bool
		err        error
		wantProbes int64
	}{
		{
			name:       "enabled by default",
			wantProbes: 1,
		},
		{
			name:       "disabled by config",
			disable:    true,
			wantProbes: 0,
		},
		{
			name:       "no socks server",
			nilServer:  true,
			wantProbes: 0,
		},
		{
			name:       "a failed warm-up is swallowed",
			err:        errors.New("probe failed"),
			wantProbes: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shortWarmUpStartDelay(t, 0)
			calls, done := stubWarmUp(t, tt.err)

			cfg := testConfig()
			cfg.Transport.DisableWarmUp = tt.disable

			core := &Core{cfg: cfg}
			if !tt.nilServer {
				core.SocksServer = &proxy.Socks5Server{}
			}

			// 按约定尽力而为：startWarmUp 从不阻塞也不会 panic。
			core.startWarmUp()

			if tt.wantProbes > 0 {
				done.waitProbe(t, "the warm-up probe")
			}
			if got := calls.Load(); got != tt.wantProbes {
				t.Fatalf("warm-up ran %d times, want %d", got, tt.wantProbes)
			}
		})
	}
}

// TestStartWarmUpWaitStartDelay 验证探测会被 config.WarmUpStartDelay 推迟：
// 主机有时间建立网络路径，探测不会仅仅因为这个原因而失败。
func TestStartWarmUpWaitStartDelay(t *testing.T) {
	shortWarmUpStartDelay(t, 100*time.Millisecond)
	calls, done := stubWarmUp(t, nil)

	core := &Core{cfg: testConfig(), SocksServer: &proxy.Socks5Server{}}
	core.startWarmUp()

	if got := calls.Load(); got != 0 {
		t.Fatalf("warm-up probe fired before the start delay, ran %d times", got)
	}

	done.waitProbe(t, "the delayed warm-up probe")
	if got := calls.Load(); got != 1 {
		t.Fatalf("warm-up probe ran %d times, want 1", got)
	}
}

// TestStopCancelsPendingWarmUp 验证关闭路径：仍在等待启动延迟的预热会被
// Stop 执行的取消操作丢弃，因此短命的核心绝不会针对已拆除的传输层探测。
//
// 该测试直接调用取消路径而不是 Core.Stop：取消预热是 Stop 做的第一件事，
// 而 Stop 的其余部分会拆除这个裸 Core 并不拥有的活动服务器。
func TestStopCancelsPendingWarmUp(t *testing.T) {
	// 足够长，使得探测只有在取消失败时才会触发。
	shortWarmUpStartDelay(t, 5*time.Second)
	calls, _ := stubWarmUp(t, nil)

	core := &Core{cfg: testConfig(), SocksServer: &proxy.Socks5Server{}}
	core.startWarmUp()

	done := make(chan struct{})
	go func() {
		core.cancelWarmUp()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop blocked on the warm-up")
	}

	if got := calls.Load(); got != 0 {
		t.Fatalf("warm-up probe ran despite the cancel, ran %d times", got)
	}
	if left := warmUpCancelOf(core); left != nil {
		t.Fatal("the cancel did not clear the recorded warm-up cancel func")
	}
}

// warmUpCancelOf 快照已派发预热的 cancel func。
func warmUpCancelOf(c *Core) context.CancelFunc {
	c.warmUpMu.Lock()
	defer c.warmUpMu.Unlock()
	return c.warmUpCancel
}

// TestStopCancelsInFlightWarmUp 验证 Stop 也会取消已经开始执行的探测：
// 当 Stop 返回时预热 context 已完成，因此遵守 ctx 的传输层会停止，
// 而不是与正在关闭的核心竞争。Stop 也绝不能阻塞在探测上。
func TestStopCancelsInFlightWarmUp(t *testing.T) {
	shortWarmUpStartDelay(t, 0)
	calls, done := stubWarmUp(t, nil)

	core := &Core{cfg: testConfig(), SocksServer: &proxy.Socks5Server{}}
	core.startWarmUp()

	cancel := warmUpCancelOf(core)
	if cancel == nil {
		t.Fatal("startWarmUp did not record a cancel func")
	}
	done.waitProbe(t, "the in-flight warm-up probe")
	if got := calls.Load(); got != 1 {
		t.Fatalf("warm-up probe ran %d times, want 1", got)
	}

	// Stop 取消预热 context 并立即返回，不等待可能仍在进行中的探测。
	stopped := make(chan struct{})
	go func() {
		core.cancelWarmUp()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop blocked on the in-flight warm-up")
	}

	if left := warmUpCancelOf(core); left != nil {
		t.Fatal("Stop did not clear the recorded warm-up cancel func")
	}
}

// TestResolveServerDomain 通过注入 prePopulateServerDomain 覆盖启动时的
// 服务器域名解析，确保测试中永远不会发出真实的 DNS 查询。
// 解析失败是致命错误（服务器不可达）。
func TestResolveServerDomain(t *testing.T) {
	oldFn := prePopulateServerDomain
	oldTimeout := serverStartupResolveTimeout
	oldDelay := serverStartupRetryDelay
	t.Cleanup(func() {
		prePopulateServerDomain = oldFn
		serverStartupResolveTimeout = oldTimeout
		serverStartupRetryDelay = oldDelay
	})
	serverStartupResolveTimeout = 50 * time.Millisecond
	serverStartupRetryDelay = 0

	// 字面 IP 无需解析：不触碰 DNS 直接跳过。
	cfgIP := testConfig() // Address 是 127.0.0.1
	attempts := 0
	prePopulateServerDomain = func(*proxy.Socks5Server, context.Context, string, []string, bool) error {
		attempts++
		return nil
	}
	c := &Core{}
	if err := c.resolveServerDomain(cfgIP); err != nil {
		t.Fatalf("IP address should not resolve: %v", err)
	}
	if attempts != 0 {
		t.Fatalf("IP address should not query DNS, got %d attempts", attempts)
	}

	// 没有默认服务器：跳过。
	cfgNone := testConfig()
	cfgNone.Servers = nil
	c = &Core{}
	if err := c.resolveServerDomain(cfgNone); err != nil {
		t.Fatalf("no server should not resolve: %v", err)
	}

	// 非 TUN 模式失败：仅一次有界尝试，返回致命错误。
	cfgDomain := testConfig()
	cfgDomain.Servers[0].Address = "proxy.example.com"
	cfgDomain.Local.EnableTun2socks = false
	prePopulateServerDomain = func(*proxy.Socks5Server, context.Context, string, []string, bool) error {
		attempts++
		return errors.New("dns boom")
	}
	attempts = 0
	c = &Core{SocksServer: &proxy.Socks5Server{}}
	err := c.resolveServerDomain(cfgDomain)
	if err == nil {
		t.Fatal("expected error on resolution failure")
	}
	if !strings.Contains(err.Error(), "resolution failed") {
		t.Fatalf("unexpected error text: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("non-TUN should attempt once, got %d", attempts)
	}

	// TUN 模式失败：重试 3 次（那里的预填充是必需的）。
	cfgTun := testConfig()
	cfgTun.Servers[0].Address = "proxy.example.com"
	cfgTun.Local.EnableTun2socks = true
	attempts = 0
	c = &Core{SocksServer: &proxy.Socks5Server{}}
	if err := c.resolveServerDomain(cfgTun); err == nil {
		t.Fatal("expected error on TUN resolution failure")
	}
	if attempts != 3 {
		t.Fatalf("TUN should attempt 3 times, got %d", attempts)
	}

	// 成功：无错误。
	prePopulateServerDomain = func(*proxy.Socks5Server, context.Context, string, []string, bool) error {
		attempts++
		return nil
	}
	attempts = 0
	c = &Core{SocksServer: &proxy.Socks5Server{}}
	if err := c.resolveServerDomain(cfgDomain); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected a single successful attempt, got %d", attempts)
	}

	// 未配置 DNS 服务器：按解析失败处理。
	oldDirect := config.DirectDNSServers
	config.DirectDNSServers = nil
	t.Cleanup(func() { config.DirectDNSServers = oldDirect })
	attempts = 0
	c = &Core{SocksServer: &proxy.Socks5Server{}}
	if err := c.resolveServerDomain(cfgDomain); err == nil {
		t.Fatal("expected error when no dns servers configured")
	}
	if attempts != 0 {
		t.Fatalf("no dns servers should short-circuit without attempts, got %d", attempts)
	}
}

// TestRunFailsOnServerDomainResolve 验证服务器域名解析失败会中止启动：
// Run 返回致命错误而不是启动服务器，因为没有它代理无法工作。
func TestRunFailsOnServerDomainResolve(t *testing.T) {
	oldFn := prePopulateServerDomain
	oldTimeout := serverStartupResolveTimeout
	oldDelay := serverStartupRetryDelay
	t.Cleanup(func() {
		prePopulateServerDomain = oldFn
		serverStartupResolveTimeout = oldTimeout
		serverStartupRetryDelay = oldDelay
	})
	serverStartupResolveTimeout = 50 * time.Millisecond
	serverStartupRetryDelay = 0

	cfg := testConfig()
	cfg.Servers[0].Address = "proxy.example.com"
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = 0

	prePopulateServerDomain = func(*proxy.Socks5Server, context.Context, string, []string, bool) error {
		return errors.New("dns boom")
	}

	core, err := Run(cfg)
	if err == nil {
		core.Stop()
		t.Fatal("expected Run to fail when the server domain cannot resolve")
	}
	if !strings.Contains(err.Error(), "resolution failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
