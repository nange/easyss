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
	"github.com/nange/easyss/v3/client/dns"
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

// TestForwardDNSListenAddr 钉住 forward DNS 的监听地址：必须是所有网卡上的
// 53 端口。只监听回环（历史上的 127.0.0.1:53）会让该功能的既定场景不可用——
// LAN 设备的 DNS 指向路由器时根本连不上这个解析器。这里只断言地址本身，
// 不去真的绑定 53 端口（CI 环境不一定允许，也可能被 dnsmasq/systemd-resolved
// 占着）。
func TestForwardDNSListenAddr(t *testing.T) {
	addr := forwardDNSListenAddr()
	if addr != ":53" {
		t.Fatalf("forwardDNSListenAddr() = %q, want \":53\"", addr)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	// 通配地址：空 host 等价于 0.0.0.0，绝不能被写成某个具体网卡地址。
	if host != "" {
		t.Errorf("forward dns must listen on all interfaces, got host %q", host)
	}
	if port != "53" {
		t.Errorf("forward dns must listen on port 53, got %q", port)
	}
}

// TestForwardDNSListenErrorMentionsPortConflict 验证 53 端口冲突的错误信息
// 带上排查方向：路由器上最常见的占用者是 dnsmasq/systemd-resolved，用户只看
// 到裸的 "address already in use" 无法知道下一步该做什么。
func TestForwardDNSListenErrorMentionsPortConflict(t *testing.T) {
	sentinel := errors.New("bind: address already in use")
	err := forwardDNSListenError(":53", sentinel)

	for _, want := range []string{":53", "dnsmasq", "systemd-resolved", "enable_forward_dns"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must mention %q", err, want)
		}
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error must wrap the original bind error, got %v", err)
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

// TestResolveServerDomain 通过注入 prePopulateServerDomain 覆盖启动时的
// 服务器域名解析，确保测试中永远不会发出真实的 DNS 查询。
// 它只做一次有界尝试，失败以错误返回（是否致命由 Run 决定，见
// TestRunDegradesWhenServerDomainUnresolved）。
func TestResolveServerDomain(t *testing.T) {
	oldFn := prePopulateServerDomain
	oldTimeout := serverStartupResolveTimeout
	t.Cleanup(func() {
		prePopulateServerDomain = oldFn
		serverStartupResolveTimeout = oldTimeout
	})
	serverStartupResolveTimeout = 50 * time.Millisecond

	// 字面 IP 无需解析：不触碰 DNS 直接跳过。
	cfgIP := testConfig() // Address 是 127.0.0.1
	attempts := 0
	prePopulateServerDomain = func(*dns.Cache, context.Context, string, []string, bool) error {
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

	// 没有本地 socks5 服务：没有可预填充的 DNS 缓存，跳过。
	cfgDomain := testConfig()
	cfgDomain.Servers[0].Address = "proxy.example.com"
	c = &Core{}
	if err := c.resolveServerDomain(cfgDomain); err != nil {
		t.Fatalf("no socks5 server should not resolve: %v", err)
	}

	// 非 TUN 模式失败：仅一次有界尝试，返回错误。
	cfgDomain.Local.EnableTun2socks = false
	prePopulateServerDomain = func(*dns.Cache, context.Context, string, []string, bool) error {
		attempts++
		return errors.New("dns boom")
	}
	attempts = 0
	c = &Core{dnsCache: dns.NewCache("")}
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

	// TUN 模式失败同样只尝试一次：重试由 Run 派发到后台，不再阻塞启动。
	cfgTun := testConfig()
	cfgTun.Servers[0].Address = "proxy.example.com"
	cfgTun.Local.EnableTun2socks = true
	attempts = 0
	c = &Core{dnsCache: dns.NewCache("")}
	if err := c.resolveServerDomain(cfgTun); err == nil {
		t.Fatal("expected error on TUN resolution failure")
	}
	if attempts != 1 {
		t.Fatalf("TUN should attempt once (retries happen in the background), got %d", attempts)
	}

	// 成功：无错误。
	prePopulateServerDomain = func(*dns.Cache, context.Context, string, []string, bool) error {
		attempts++
		return nil
	}
	attempts = 0
	c = &Core{dnsCache: dns.NewCache("")}
	if err := c.resolveServerDomain(cfgDomain); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected a single successful attempt, got %d", attempts)
	}

	// 未配置 DNS 服务器：直接返回错误且不尝试。
	oldDirect := config.DirectDNSServers
	config.DirectDNSServers = nil
	t.Cleanup(func() { config.DirectDNSServers = oldDirect })
	attempts = 0
	c = &Core{dnsCache: dns.NewCache("")}
	if err := c.resolveServerDomain(cfgDomain); err == nil {
		t.Fatal("expected error when no dns servers configured")
	}
	if attempts != 0 {
		t.Fatalf("no dns servers should short-circuit without attempts, got %d", attempts)
	}
}

// setShortDomainRetry 把后台重试的时序参数与外部副作用缩到测试尺度，
// 并在测试结束时还原。
func setShortDomainRetry(t *testing.T) {
	t.Helper()

	oldBase, oldMax := serverDomainRetryBase, serverDomainRetryMax
	oldTimeout := serverStartupResolveTimeout
	oldReset := resetResolveState
	t.Cleanup(func() {
		serverDomainRetryBase, serverDomainRetryMax = oldBase, oldMax
		serverStartupResolveTimeout = oldTimeout
		resetResolveState = oldReset
	})

	serverStartupResolveTimeout = 50 * time.Millisecond
	serverDomainRetryBase = 10 * time.Millisecond
	serverDomainRetryMax = 20 * time.Millisecond
	// DNS 包的熔断/系统 DNS 缓存是进程级状态，测试里不触碰它。
	resetResolveState = func() {}
}

// TestRunDegradesWhenServerDomainUnresolved 验证服务器域名解析失败不再中止
// 启动：Run 正常返回核心，警告带上专用哨兵，后台重试成功后关闭就绪通道。
func TestRunDegradesWhenServerDomainUnresolved(t *testing.T) {
	oldFn := prePopulateServerDomain
	t.Cleanup(func() { prePopulateServerDomain = oldFn })
	setShortDomainRetry(t)

	var (
		mu       sync.Mutex
		attempts int
		resets   int
	)
	prePopulateServerDomain = func(*dns.Cache, context.Context, string, []string, bool) error {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts < 3 {
			return errors.New("dns boom")
		}
		return nil
	}
	resetResolveState = func() {
		mu.Lock()
		defer mu.Unlock()
		resets++
	}

	cfg := testConfig()
	cfg.Servers[0].Address = "proxy.example.com"
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = 0

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run must not fail when the server domain is unresolved: %v", err)
	}
	defer core.Stop()

	if !errors.Is(core.StartupWarn, ErrServerDomainUnresolved) {
		t.Fatalf("StartupWarn = %v, want ErrServerDomainUnresolved", core.StartupWarn)
	}
	select {
	case <-core.ServerDomainReady():
		t.Fatal("ready channel must stay open while the domain is unresolved")
	default:
	}

	select {
	case <-core.ServerDomainReady():
	case <-time.After(5 * time.Second):
		t.Fatal("ready channel was not closed after the background retry succeeded")
	}

	mu.Lock()
	gotAttempts, gotResets := attempts, resets
	mu.Unlock()
	if gotAttempts < 3 {
		t.Fatalf("attempts = %d, want >= 3", gotAttempts)
	}
	// 前台那次尝试不清缓存；此后每次后台尝试都先清一次。
	if gotResets != gotAttempts-1 {
		t.Fatalf("resetResolveState calls = %d, want one per background attempt (%d)", gotResets, gotAttempts-1)
	}
}

// TestRunServerDomainReadyImmediately 验证无需解析（字面 IP）时启动即就绪，
// 且不会派发任何后台解析尝试。
func TestRunServerDomainReadyImmediately(t *testing.T) {
	oldFn := prePopulateServerDomain
	t.Cleanup(func() { prePopulateServerDomain = oldFn })
	setShortDomainRetry(t)

	var attempts atomic.Int64
	prePopulateServerDomain = func(*dns.Cache, context.Context, string, []string, bool) error {
		attempts.Add(1)
		return nil
	}

	cfg := testConfig() // Address 是字面 IP
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = 0

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer core.Stop()

	if core.StartupWarn != nil {
		t.Fatalf("StartupWarn = %v, want nil", core.StartupWarn)
	}
	select {
	case <-core.ServerDomainReady():
	default:
		t.Fatal("ready channel must be closed for a literal server IP")
	}

	time.Sleep(5 * serverDomainRetryMax)
	if got := attempts.Load(); got != 0 {
		t.Fatalf("literal IP must not trigger resolution attempts, got %d", got)
	}
}

// TestServerDomainRetryStopsOnStop 验证核心停止后后台重试不再发起新的解析。
func TestServerDomainRetryStopsOnStop(t *testing.T) {
	oldFn := prePopulateServerDomain
	t.Cleanup(func() { prePopulateServerDomain = oldFn })
	setShortDomainRetry(t)

	var attempts atomic.Int64
	prePopulateServerDomain = func(*dns.Cache, context.Context, string, []string, bool) error {
		attempts.Add(1)
		return errors.New("dns boom")
	}

	cfg := testConfig()
	cfg.Servers[0].Address = "proxy.example.com"
	cfg.Local.SocksPort = freePort(t)
	cfg.Local.HTTPPort = 0

	core, err := Run(cfg)
	if err != nil {
		t.Fatalf("Run must not fail when the server domain is unresolved: %v", err)
	}

	// 等到后台确实在重试。
	deadline := time.Now().Add(5 * time.Second)
	for attempts.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("background retry never started")
		}
		time.Sleep(2 * time.Millisecond)
	}

	core.Stop()

	// 让进行中的那次尝试收尾（最坏 serverStartupResolveTimeout），随后取样两次：
	// 停止之后不允许再出现新的尝试。
	time.Sleep(3 * serverStartupResolveTimeout)
	settled := attempts.Load()
	time.Sleep(5 * serverDomainRetryMax)
	if got := attempts.Load(); got != settled {
		t.Fatalf("retry kept running after Stop: %d -> %d", settled, got)
	}
}
