package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/nange/easyss/v3/client"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/proxy"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
)

var errSocksRequired = errors.New("http proxy requires socks_port to be enabled")

// serverStartupResolveTimeout 限定启动时每次同步的服务器域名解析尝试。
// 它与 client.serverIPV6ResolveTimeout 保持一致：3s 对健康的网络足够，
// 同时能把最坏情况下的启动延迟控制得很短。serverStartupRetryDelay 是
// TUN 模式下重试之间的停顿时间。两者都是变量（而非常量），以便测试缩短它们。
var (
	serverStartupResolveTimeout = 3 * time.Second
	serverStartupRetryDelay     = time.Second
)

// prePopulateServerDomain 是包级变量，以便测试注入确定性的失败
// （与 client.boundDialContext 采用相同模式）。
var prePopulateServerDomain = func(s *proxy.Socks5Server, ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error {
	return s.PrePopulateDNS(ctx, domain, dnsServers, requireIPv4)
}

// warmUpCore 预热本地 SOCKS5 服务器背后的传输连接池。它是包级变量，
// 以便测试在没有任何网络的情况下断言调度行为。
var warmUpCore = func(s *proxy.Socks5Server, timeout time.Duration) error {
	return s.WarmUp(timeout)
}

// warmUpStartDelay 与 config.WarmUpStartDelay 保持一致：预热在 goroutine
// 中派发，先等待这段时间再发起探测，让主机有时间完成网络路径的建立。
// 它是变量（而非常量），以便测试缩短它，与 serverStartupResolveTimeout
// 采用相同模式。
var warmUpStartDelay = sharedconfig.WarmUpStartDelay

type Core struct {
	cfg           *config.ClientConfig
	Client        *client.Client
	SocksServer   *proxy.Socks5Server
	HTTPServer    *proxy.HTTPProxyServer
	StreamHandler *proxy.StreamHandler
	dnsServer     *dns.ForwardServer

	// StartupWarn 保存初始化核心时检测到的非致命警告（例如自定义规则文件
	// 加载失败），调用方可以在不中断启动的情况下将其展示给用户。
	StartupWarn error

	// warmUpCancel 取消由 startWarmUp 启动的进行中（或仍在延迟中的）后台
	// 预热；只设置一次，由 Stop 调用。由 warmUpMu 保护，因为 Stop 可能在
	// Run 仍在派发时执行。
	warmUpMu     sync.Mutex
	warmUpCancel context.CancelFunc
}

func Run(cfg *config.ClientConfig) (*Core, error) {
	start := time.Now()

	cli, err := client.New(cfg)
	if err != nil {
		return nil, err
	}
	log.Info("[EASYSS] client core ready", "elapsed_ms", time.Since(start).Milliseconds())

	method := protocol.MethodFromString(cfg.DefaultServer().Method)
	if method == 0 {
		method = protocol.MethodAES256GCM
	}

	shaperCfg := shaper.Config{
		BatchWindowMS: cfg.Shaper.BatchWindowMS,
		Cover: shaper.CoverConfig{
			BudgetRatio: cfg.Shaper.CoverBudgetRatio,
			BudgetCap:   cfg.Shaper.CoverBudgetCap,
		},
	}

	timeouts := sharedconfig.NewTimeouts(cfg.TimeoutDuration())

	streamHandler := proxy.NewStreamHandler(cli.Transport(), cli.MasterKey(), shaperCfg, timeouts.StreamIdle)

	c := &Core{
		cfg:           cfg,
		Client:        cli,
		StreamHandler: streamHandler,
		StartupWarn:   cli.StartupWarning(),
	}

	// 在启动任何服务器 goroutine 之前，预先绑定所有本地监听地址，
	// 这样监听失败（例如端口已被占用）会以错误中止启动，
	// 而不是被记录日志后静默忽略。
	var socksAddr, httpAddr, dnsAddr string
	if cfg.Local.SocksPort > 0 {
		socksAddr = "127.0.0.1:" + strconv.Itoa(cfg.Local.SocksPort)
		if cfg.Local.BindAll {
			socksAddr = "[::]:" + strconv.Itoa(cfg.Local.SocksPort)
		}
		if err := prebindTCP(socksAddr); err != nil {
			c.cleanup()
			return nil, fmt.Errorf("socks5 server listen %s: %w", socksAddr, err)
		}
	}
	if cfg.Local.HTTPPort > 0 {
		if cfg.Local.SocksPort <= 0 {
			_ = cli.Close()
			return nil, errSocksRequired
		}
		httpAddr = "127.0.0.1:" + strconv.Itoa(cfg.Local.HTTPPort)
		if cfg.Local.BindAll {
			httpAddr = "[::]:" + strconv.Itoa(cfg.Local.HTTPPort)
		}
		if err := prebindTCP(httpAddr); err != nil {
			c.cleanup()
			return nil, fmt.Errorf("http proxy server listen %s: %w", httpAddr, err)
		}
	}
	if cfg.Local.EnableForwardDNS {
		dnsAddr = "127.0.0.1:53"
		if err := prebindUDP(dnsAddr); err != nil {
			c.cleanup()
			return nil, fmt.Errorf("dns forward server listen %s: %w", dnsAddr, err)
		}
	}

	if socksAddr != "" {
		serverDomain := ""
		if svr := cfg.DefaultServer(); svr != nil && !util.IsIP(svr.Address) {
			serverDomain = svr.Address
		}
		socksServer, err := proxy.NewSocks5Server(proxy.Socks5Options{
			ListenAddr:        socksAddr,
			Username:          cfg.AuthUsername,
			Password:          cfg.AuthPassword,
			Handler:           streamHandler,
			Router:            cli.Router(),
			ServerDomain:      serverDomain,
			Method:            method,
			DisableQUIC:       !cfg.Local.EnableQUIC,
			Timeouts:          timeouts,
			DirectDialContext: cli.DialContext,
		})
		if err != nil {
			_ = cli.Close()
			return nil, err
		}
		c.SocksServer = socksServer
		log.Info("[EASYSS] starting socks5 server", "addr", socksAddr)
		c.SocksServer.MarkStarted()
		go func() {
			if err := c.SocksServer.Start(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Error("[EASYSS] socks5 server", "err", err)
			}
		}()
	}

	if httpAddr != "" {
		socksAddr := "127.0.0.1:" + strconv.Itoa(cfg.Local.SocksPort)
		httpServer, err := proxy.NewHTTPProxyServer(proxy.HTTPProxyOptions{
			ListenAddr: httpAddr,
			SocksAddr:  socksAddr,
			Username:   cfg.AuthUsername,
			Password:   cfg.AuthPassword,
			Timeout:    timeouts.Base,
			Handler:    streamHandler,
			Router:     cli.Router(),
			Method:     method,
			Dial:       cli.DialContext,
		})
		if err != nil {
			c.cleanup()
			return nil, err
		}
		c.HTTPServer = httpServer
		log.Info("[EASYSS] starting http proxy server", "addr", httpAddr)
		go func() {
			if err := c.HTTPServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("[EASYSS] http proxy server", "err", err)
			}
		}()
	}

	if dnsAddr != "" {
		c.dnsServer = dns.NewForwardServer(dnsAddr, cli.Router().ShouldIPV6Disable())
		log.Info("[EASYSS] starting dns forward server", "addr", dnsAddr)
		go func() {
			if err := c.dnsServer.Start(); err != nil {
				log.Error("[EASYSS] dns forward server", "err", err)
			}
		}()
	}

	// 服务器域名必须能解析，代理路径才能工作，因此解析检查属于核心启动
	// 的一部分。解析失败意味着服务器不可达、代理无法工作，因此它和其他
	// 致命的核心错误一样会中止启动。
	if err := c.resolveServerDomain(cfg); err != nil {
		c.cleanup()
		return nil, err
	}

	log.Info("[EASYSS] started successfully", "elapsed_ms", time.Since(start).Milliseconds())
	// 开启一个全新的统计会话：进程可能经历多次启动/停止周期（例如
	// Android），因此同时重置会话开始时间和所有计数器。
	stats.ResetStartTime()
	stats.ResetCounters()
	stats.StartSpeedMonitor()
	// 最后再派发后台预热：它只预热连接池，绝不能延迟或导致启动失败。
	c.startWarmUp()
	return c, nil
}

// startWarmUp 在后台派发传输层连接池的预热，使每种流量类型的第一个真实
// 流都能复用已建立的连接。它会立即返回：调用方（桌面端启动、gomobile
// Start）永远不会被它阻塞，也不应依赖它——探测在 config.WarmUpStartDelay
// 之后才执行，其失败只会被记录日志。预热被禁用（transport.disable_warm_up）
// 或核心没有本地 SOCKS5 代理（socks_port = 0）时会被跳过，而不会失败。
//
// 预热 goroutine 由 Stop 取消，因此短命的核心（启动后立即停止，如测试和
// 快速切换服务器时）绝不会留下一个针对已关闭传输层的探测在运行。
func (c *Core) startWarmUp() {
	if c == nil || c.cfg == nil || c.SocksServer == nil {
		return
	}
	if c.cfg.Transport.DisableWarmUp {
		log.Info("[EASYSS] warm-up disabled by config")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	// goroutine 需要的一切都在它启动前捕获完成。Stop 会并发地拆除核心，
	// 探测必须针对本次调用派发时的服务器（预热一个 Close 已执行的服务器
	// 是无害的：它会因 closing 标志提前返回），而 warmUpCore/warmUpStartDelay
	// 是测试在两次派发之间会替换的包级变量——从 goroutine 中读取它们会与
	// 下一个测试产生数据竞争。
	socksServer := c.SocksServer
	probe := warmUpCore
	delay := warmUpStartDelay

	c.warmUpMu.Lock()
	c.warmUpCancel = cancel
	c.warmUpMu.Unlock()

	go func() {
		defer cancel()

		select {
		case <-time.After(delay):
		case <-ctx.Done():
			// 在探测发出之前就停止了：被跳过的预热不算失败。
			log.Debug("[EASYSS] warm-up skipped, core stopping")
			return
		}

		if err := probe(socksServer, sharedconfig.WarmUpTimeout); err != nil {
			log.Warn("[EASYSS] warm-up failed (non-fatal)", "err", err)
		}
	}()
}

// cancelWarmUp 取消后台预热（如果已派发）。对从未启动过预热的核心调用
// 它是安全的，重复调用也是安全的（context.CancelFunc 是幂等的）。
func (c *Core) cancelWarmUp() {
	c.warmUpMu.Lock()
	cancel := c.warmUpCancel
	c.warmUpCancel = nil
	c.warmUpMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

func (c *Core) Stop() {
	// 在拆除任何东西之前先取消预热，使仍在延迟中或进行中的探测停止，
	// 而不是与正在关闭的传输层竞争。
	c.cancelWarmUp()
	c.cleanup()
	log.Info("[EASYSS] stopped")
}

// resolveServerDomain 通过直连 DNS 服务器（带系统 DNS 兜底）预先解析代理
// 服务器主机名并预填充 DNS 缓存，使代理路径永远不会等待冷查询。失败会以
// 致命错误返回：域名无法解析时服务器不可达、代理完全无法工作，因此调用方
// 中止启动。
//
// TUN 模式会重试（3 次），因为一旦系统 DNS 切换到转发服务器，那里的预填充
// 失败会导致 TUN DNS 死锁；非 TUN 模式则是尽力而为，只做一次有界尝试。
// 字面 IP 地址无需解析，直接返回 nil。
func (c *Core) resolveServerDomain(cfg *config.ClientConfig) error {
	svr := cfg.DefaultServer()
	if svr == nil || util.IsIP(svr.Address) {
		return nil
	}
	if c.SocksServer == nil {
		return nil
	}

	attempts := 1
	if cfg.Local.EnableTun2socks {
		attempts = 3
	}

	start := time.Now()
	var err error
	for i := range attempts {
		if len(config.DirectDNSServers) == 0 {
			err = errors.New("no direct dns servers configured")
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), serverStartupResolveTimeout)
		err = prePopulateServerDomain(c.SocksServer, ctx, svr.Address, config.DirectDNSServers,
			cfg.Routing.IPV6Rule != "enable")
		cancel()
		if err == nil {
			break
		}
		if i < attempts-1 {
			time.Sleep(serverStartupRetryDelay)
		}
	}

	if err != nil {
		log.Warn("[EASYSS] server domain resolution failed at startup",
			"host", svr.Address,
			"elapsed_ms", time.Since(start).Milliseconds(),
			"err", err,
		)
		return fmt.Errorf("server domain %s resolution failed: %w", svr.Address, err)
	}
	log.Info("[EASYSS] server domain resolved at startup",
		"host", svr.Address,
		"elapsed_ms", time.Since(start).Milliseconds(),
	)
	return nil
}

// prebindTCP 在服务器 goroutine 启动前验证给定的 TCP 地址可绑定，
// 使监听失败（例如端口已被占用）能快速以错误失败，
// 而不是被记录日志后静默忽略。
func prebindTCP(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return l.Close()
}

// prebindUDP 是 prebindTCP 的 UDP 对应版本，供监听 UDP 的 DNS
// 转发服务器使用。
func prebindUDP(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	return pc.Close()
}

func (c *Core) cleanup() {
	if c.SocksServer != nil {
		_ = c.SocksServer.Close()
	}
	if c.HTTPServer != nil {
		_ = c.HTTPServer.Close()
	}
	if c.dnsServer != nil {
		_ = c.dnsServer.Shutdown()
	}
	if c.Client != nil {
		_ = c.Client.Close()
	}
	// 不再有活跃会话，因此也不再需要会话开始时间。
	stats.ClearStartTime()
	stats.StopSpeedMonitor()
}
