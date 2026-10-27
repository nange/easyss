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

	"github.com/miekg/dns"
	clientconfig "github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/config"
)

func testConfig() *clientconfig.ClientConfig {
	// 字面 IP 让 resolveServerDomain 与 client.New 的 IPv6 解析直接跳过，测试因此
	// 不会发出真实 DNS 查询。
	cfg, err := clientconfig.BuildSimpleConfig(&config.SimpleConfig{
		Server:   "127.0.0.1",
		Password: "test-password",
	})
	if err != nil {
		panic(err)
	}
	// 跳过客户端初始化期间通过直连 DNS 服务器进行的 IPv6 解析，
	// 否则测试中每次查询都会阻塞数秒。
	cfg.Routing.IPV6Rule = "disable"
	return cfg
}

// TestStopImmediatelyAfterRun 守住 Socks5Server.Close 与 Start 的 accept 循环初始化
// 之间的死锁：GOMAXPROCS(1) 让主 goroutine 先跑到 Shutdown，确定性地暴露该竞争。
func TestStopImmediatelyAfterRun(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)

	for range 5 {
		cfg := testConfig()
		cfg.Local.HTTPPort = 0

		core := startRetrying(t, func() (*Core, error) {
			cfg.Local.SocksPort = freePort(t)
			return Run(cfg)
		})
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

// freePortPair 同时占住两个端口再一起释放：分两次 freePort 时第一个监听器已经
// 关闭，内核可能把同一个端口再分回来，而 Run 要用它们分别 bind SOCKS 与 HTTP。
func freePortPair(t *testing.T) (int, int) {
	t.Helper()

	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer first.Close() //nolint:errcheck

	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer second.Close() //nolint:errcheck

	return first.Addr().(*net.TCPAddr).Port, second.Addr().(*net.TCPAddr).Port
}

// listenRetries 是临时端口被同机其它测试抢走时的重试上限。
const listenRetries = 3

// isListenError 报告错误是否来自本地端点绑定（端口占用、fd 耗尽等）。
func isListenError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "listen"
}

// startRetrying 反复用新端口启动，直到不再撞上"探测后被抢走"的临时端口：freePort
// 只保证探测那一刻可绑定，到 Run 真正 bind 之间隔着 client.New 的初始化。启动失败
// 返回的 Run 已自行释放监听器，因此换一组端口重试是安全的。
func startRetrying(t *testing.T, start func() (*Core, error)) *Core {
	t.Helper()

	for attempt := 1; ; attempt++ {
		core, err := start()
		if err == nil {
			return core
		}
		if !isListenError(err) || attempt == listenRetries {
			t.Fatalf("Run failed after %d attempt(s): %v", attempt, err)
		}
	}
}

// runExpectingListenError 用于"某个端口被占住、Run 必须失败"的用例：另一个由
// freePort 挑出的端口可能先被抢走，让 Run 报出无关的监听错误，此时换端口重试。
// 期望的冲突一直存在，真正的回归会稳定复现。
func runExpectingListenError(t *testing.T, want string, start func() (*Core, error)) {
	t.Helper()

	for attempt := 1; ; attempt++ {
		core, err := start()
		if err == nil {
			core.Stop()
			t.Fatalf("Run succeeded, want a listen error containing %q", want)
		}
		if strings.Contains(err.Error(), want) {
			return
		}
		if !isListenError(err) || attempt == listenRetries {
			t.Fatalf("Run failed with %v, want a listen error containing %q", err, want)
		}
	}
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
	cfg.Local.HTTPPort = httpPort

	runExpectingListenError(t, "http proxy server listen", func() (*Core, error) {
		cfg.Local.SocksPort = freePort(t)
		return Run(cfg)
	})
}

// TestRunValidatesHTTPWithoutSocksBeforeBinding 守住"先校验后绑定"：HTTP 需要 SOCKS5
// 是配置错误，必须在任何监听器绑定之前返回。两个子用例分别占用 HTTP/DNS 端口，校验若
// 被挪到对应绑定之后，错误会变成绑定失败而不是 ErrSocksRequired。
func TestRunValidatesHTTPWithoutSocksBeforeBinding(t *testing.T) {
	t.Run("http port occupied", func(t *testing.T) {
		_, httpPort := occupyTCPPort(t)
		cfg := testConfig()
		cfg.Local.SocksPort = 0
		cfg.Local.HTTPPort = httpPort

		core, err := Run(cfg)
		if core != nil {
			core.Stop()
			t.Fatal("expected no core when socks_port is disabled")
		}
		if !errors.Is(err, ErrSocksRequired) {
			t.Fatalf("expected ErrSocksRequired before binding, got: %v", err)
		}
	})

	t.Run("forward dns port occupied", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen packet: %v", err)
		}
		defer pc.Close() //nolint:errcheck

		opts := defaultOptions()
		opts.forwardDNSListenAddr = pc.LocalAddr().String()

		cfg := testConfig()
		cfg.Local.SocksPort = 0
		cfg.Local.HTTPPort = freePort(t)
		cfg.Local.EnableForwardDNS = true

		core, err := runWithOptions(cfg, opts)
		if core != nil {
			core.Stop()
			t.Fatal("expected no core when socks_port is disabled")
		}
		if !errors.Is(err, ErrSocksRequired) {
			t.Fatalf("expected ErrSocksRequired before binding, got: %v", err)
		}
	})
}

// TestRunRejectsForwardDNSWithoutTun 守住启动前提：forward DNS 只用于路由器透明代理，
// LAN 查询要靠 TUN 重新进入隧道，缺 TUN 或本地 socks5 入口时只剩直连解析（DNS 泄漏），
// 必须拒绝启动而不是降级。占住 forward DNS 端口，校验若被挪到绑定之后会变成绑定错误。
func TestRunRejectsForwardDNSWithoutTun(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	defer pc.Close() //nolint:errcheck

	opts := defaultOptions()
	opts.forwardDNSListenAddr = pc.LocalAddr().String()

	// 两个前提分别缺一：tun2socks 关着，或 socks_port 关着（没有本地 socks5 入口）。
	cases := []struct {
		name      string
		socksPort int
		enableTun bool
	}{
		{name: "tun disabled", socksPort: freePort(t), enableTun: false},
		{name: "socks disabled", socksPort: 0, enableTun: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Local.HTTPPort = 0
			cfg.Local.EnableForwardDNS = true
			cfg.Local.SocksPort = tc.socksPort
			cfg.Local.EnableTun2socks = tc.enableTun

			core, err := runWithOptions(cfg, opts)
			if core != nil {
				core.Stop()
				t.Fatal("expected no core when forward dns prerequisites are missing")
			}
			if !errors.Is(err, ErrForwardDNSRequiresTun) {
				t.Fatalf("expected ErrForwardDNSRequiresTun before binding, got: %v", err)
			}
		})
	}
}

// TestRunFailsFastOnForwardDNSConflict 守住 forward DNS 绑定失败同样中止 Run（与
// SOCKS5/HTTP 一样在 Run 里同步绑定）；注入回环临时端口是因为绑定 :53 需要 root。
func TestRunFailsFastOnForwardDNSConflict(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	defer pc.Close() //nolint:errcheck

	addr := pc.LocalAddr().String()
	opts := defaultOptions()
	opts.forwardDNSListenAddr = addr

	cfg := testConfig()
	cfg.Local.HTTPPort = 0
	cfg.Local.EnableForwardDNS = true
	cfg.Local.EnableTun2socks = true

	runExpectingListenError(t, "dns forward server listen", func() (*Core, error) {
		cfg.Local.SocksPort = freePort(t)
		return runWithOptions(cfg, opts)
	})
}

// TestRunServesForwardDNSOnInjectedAddr 覆盖成功路径：Run 同步绑定的 UDP
// socket 真的被交给 ForwardServer 并开始应答，而不是绑定后无人接管。
func TestRunServesForwardDNSOnInjectedAddr(t *testing.T) {
	opts := defaultOptions()

	cfg := testConfig()
	cfg.Local.HTTPPort = 0
	cfg.Local.EnableForwardDNS = true
	cfg.Local.EnableTun2socks = true

	var addr string
	core := startRetrying(t, func() (*Core, error) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen packet: %v", err)
		}
		addr = pc.LocalAddr().String()
		_ = pc.Close() // 让 Run 去绑定同一个地址
		opts.forwardDNSListenAddr = addr
		cfg.Local.SocksPort = freePort(t)
		return runWithOptions(cfg, opts)
	})
	t.Cleanup(core.Stop)

	// 用一个真实 DNS 查询证明 socket 已经在服务：转发服务器最终会因上游
	// 不可达而回 SERVFAIL，但"收到应答"本身就说明 Serve 已接管该 socket。
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	client := &dns.Client{Timeout: 2 * time.Second}
	var lastErr error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, _, err := client.Exchange(msg, addr)
		if err == nil && resp != nil {
			return
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the injected forward dns socket never answered: %v", lastErr)
}

// TestForwardDNSListenAddr 钉住 forward DNS 必须监听所有网卡的 53 端口：只监听回环会让
// LAN 设备（DNS 指向路由器）连不上。只断言地址，不去真的绑定 53。
func TestForwardDNSListenAddr(t *testing.T) {
	t.Parallel()

	addr := defaultOptions().forwardDNSListenAddr
	if addr != ":53" {
		t.Fatalf("forwardDNSListenAddr = %q, want \":53\"", addr)
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
	t.Parallel()

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
	core := startRetrying(t, func() (*Core, error) {
		cfg.Local.SocksPort, cfg.Local.HTTPPort = freePortPair(t)
		return Run(cfg)
	})
	core.Stop()
}

// TestResolveServerDomain 覆盖启动期解析的各条早退与失败路径，全程不发真实 DNS 查询。
func TestResolveServerDomain(t *testing.T) {
	newCore := func(opts options) *Core {
		return &Core{dnsCache: easydns.NewCache(""), opts: opts}
	}

	// 字面 IP 无需解析：不触碰 DNS 直接跳过。
	cfgIP := testConfig() // Host 是 127.0.0.1
	attempts := 0
	opts := testOptions()
	opts.prePopulate = func(*easydns.Cache, context.Context, string, []string, bool) error {
		attempts++
		return nil
	}
	if err := newCore(opts).resolveServerDomain(cfgIP); err != nil {
		t.Fatalf("IP address should not resolve: %v", err)
	}
	if attempts != 0 {
		t.Fatalf("IP address should not query DNS, got %d attempts", attempts)
	}

	// 没有默认服务器：跳过。
	cfgNone := testConfig()
	cfgNone.Servers = nil
	if err := newCore(opts).resolveServerDomain(cfgNone); err != nil {
		t.Fatalf("no server should not resolve: %v", err)
	}

	// 没有本地 socks5 服务：没有可预填充的 DNS 缓存，跳过。
	cfgDomain := testConfig()
	cfgDomain.Servers[0].Host = "proxy.example.com"
	if err := newCore(opts).resolveServerDomain(cfgDomain); err != nil {
		t.Fatalf("no socks5 server should not resolve: %v", err)
	}

	// 非 TUN 模式失败：仅一次有界尝试，返回错误。
	cfgDomain.Local.EnableTun2socks = false
	opts.prePopulate = func(*easydns.Cache, context.Context, string, []string, bool) error {
		attempts++
		return errors.New("dns boom")
	}
	attempts = 0
	err := newCore(opts).resolveServerDomain(cfgDomain)
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
	cfgTun.Servers[0].Host = "proxy.example.com"
	cfgTun.Local.EnableTun2socks = true
	attempts = 0
	if err := newCore(opts).resolveServerDomain(cfgTun); err == nil {
		t.Fatal("expected error on TUN resolution failure")
	}
	if attempts != 1 {
		t.Fatalf("TUN should attempt once (retries happen in the background), got %d", attempts)
	}

	// 成功：无错误。
	opts.prePopulate = func(*easydns.Cache, context.Context, string, []string, bool) error {
		attempts++
		return nil
	}
	attempts = 0
	if err := newCore(opts).resolveServerDomain(cfgDomain); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected a single successful attempt, got %d", attempts)
	}

	// 未配置 DNS 服务器：直接返回错误且不尝试。
	oldDirect := clientconfig.DirectDNSServers
	clientconfig.DirectDNSServers = nil
	t.Cleanup(func() { clientconfig.DirectDNSServers = oldDirect })
	attempts = 0
	if err := newCore(opts).resolveServerDomain(cfgDomain); err == nil {
		t.Fatal("expected error when no dns servers configured")
	}
	if attempts != 0 {
		t.Fatalf("no dns servers should short-circuit without attempts, got %d", attempts)
	}
}

// testOptions 把后台重试的时序缩到测试尺度；DNS 包的熔断/系统 DNS 缓存是进程级
// 状态，测试里不触碰它。
func testOptions() options {
	o := defaultOptions()
	o.startupResolveTimeout = 50 * time.Millisecond
	o.retryBase = 10 * time.Millisecond
	o.retryMax = 20 * time.Millisecond
	o.reset = func() {}
	return o
}

// TestRunDegradesWhenServerDomainUnresolved 验证服务器域名解析失败不再中止
// 启动：Run 正常返回核心，警告带上专用哨兵，后台重试成功后关闭就绪通道。
func TestRunDegradesWhenServerDomainUnresolved(t *testing.T) {
	opts := testOptions()

	var (
		mu       sync.Mutex
		attempts int
		resets   int
	)
	opts.prePopulate = func(*easydns.Cache, context.Context, string, []string, bool) error {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts < 3 {
			return errors.New("dns boom")
		}
		return nil
	}
	opts.reset = func() {
		mu.Lock()
		defer mu.Unlock()
		resets++
	}

	cfg := testConfig()
	cfg.Servers[0].Host = "proxy.example.com"
	cfg.Local.HTTPPort = 0

	core := startRetrying(t, func() (*Core, error) {
		cfg.Local.SocksPort = freePort(t)
		return runWithOptions(cfg, opts)
	})
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
		t.Fatalf("resolve-state resets = %d, want one per background attempt (%d)", gotResets, gotAttempts-1)
	}
}

// TestRunServerDomainReadyImmediately 验证无需解析（字面 IP）时启动即就绪，
// 且不会派发任何后台解析尝试。
func TestRunServerDomainReadyImmediately(t *testing.T) {
	opts := testOptions()

	var attempts atomic.Int64
	opts.prePopulate = func(*easydns.Cache, context.Context, string, []string, bool) error {
		attempts.Add(1)
		return nil
	}

	cfg := testConfig() // Host 是字面 IP
	cfg.Local.HTTPPort = 0

	core := startRetrying(t, func() (*Core, error) {
		cfg.Local.SocksPort = freePort(t)
		return runWithOptions(cfg, opts)
	})
	defer core.Stop()

	if core.StartupWarn != nil {
		t.Fatalf("StartupWarn = %v, want nil", core.StartupWarn)
	}
	select {
	case <-core.ServerDomainReady():
	default:
		t.Fatal("ready channel must be closed for a literal server IP")
	}

	time.Sleep(5 * opts.retryMax)
	if got := attempts.Load(); got != 0 {
		t.Fatalf("literal IP must not trigger resolution attempts, got %d", got)
	}
}

// TestServerDomainRetryStopsOnStop 验证核心停止后后台重试不再发起新的解析。
func TestServerDomainRetryStopsOnStop(t *testing.T) {
	opts := testOptions()

	var attempts atomic.Int64
	opts.prePopulate = func(*easydns.Cache, context.Context, string, []string, bool) error {
		attempts.Add(1)
		return errors.New("dns boom")
	}

	cfg := testConfig()
	cfg.Servers[0].Host = "proxy.example.com"
	cfg.Local.HTTPPort = 0

	core := startRetrying(t, func() (*Core, error) {
		cfg.Local.SocksPort = freePort(t)
		return runWithOptions(cfg, opts)
	})

	// 等到后台确实在重试。
	deadline := time.Now().Add(5 * time.Second)
	for attempts.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("background retry never started")
		}
		time.Sleep(2 * time.Millisecond)
	}

	core.Stop()

	// 让进行中的那次尝试收尾（最坏 startupResolveTimeout），随后取样两次：
	// 停止之后不允许再出现新的尝试。
	time.Sleep(3 * opts.startupResolveTimeout)
	settled := attempts.Load()
	time.Sleep(5 * opts.retryMax)
	if got := attempts.Load(); got != settled {
		t.Fatalf("retry kept running after Stop: %d -> %d", settled, got)
	}
}
