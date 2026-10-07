package runner

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
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
	"github.com/nange/easyss/v3/transport"
	"github.com/nange/easyss/v3/util"
)

var errSocksRequired = errors.New("http proxy requires socks_port to be enabled")

// ErrServerDomainUnresolved 标记"启动时服务端域名尚未解析成功"这一非致命启动
// 警告：进程继续运行并在后台重试解析。调用方（托盘/headless）用 errors.Is
// 判定它，以便给出"网络可能尚未就绪"的专用提示。
var ErrServerDomainUnresolved = errors.New("server domain unresolved")

// serverStartupResolveTimeout 限定启动时以及后台每次重试的服务器域名解析尝试，
// 默认取 dns.PreResolveTimeout（预解析总预算的唯一事实来源，client.New 与 TUN
// helper 也用它）。
//
// serverDomainRetryBase/serverDomainRetryMax 是后台重试的指数退避区间
// （下限、上限，带 ±20% 抖动）：开机时网络可能几十秒后才就绪，退避上限决定
// 了恢复被发现的延迟上界，同时让长时间离线时的尝试足够廉价。三者都是变量
// （而非常量），以便测试缩短它们。
var (
	serverStartupResolveTimeout = dns.PreResolveTimeout
	serverDomainRetryBase       = time.Second
	serverDomainRetryMax        = 15 * time.Second
)

// prePopulateServerDomain 是包级变量，以便测试注入确定性的失败
// （与 client.boundDialContext 采用相同模式）。缓存由 runner 自己持有：
// 预解析、DNS pinning 地址发布与代理服务器共享同一份缓存实例。
var prePopulateServerDomain = func(cache *dns.Cache, ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error {
	return cache.PrePopulateWithFallback(ctx, domain, dnsServers, requireIPv4)
}

// resetResolveState 清除 DNS 层的内置服务器熔断状态与系统 DNS 发现缓存
// （见 dns.ResetResolveState）。它是包级变量，以便测试注入空操作，
// 避免测试改动 DNS 包的进程级状态。
var resetResolveState = dns.ResetResolveState

// Core 持有一次客户端会话的全部组件，并**唯一**负责它们的关闭顺序
// （见 cleanup）：本地代理入口 -> 传输层。
//
// 字段的所有权：Client 是传输层与路由引擎的所有者；SocksServer/HTTPServer 与
// StreamHandler 只借用它们（各自的 Close 明确不关闭借来的依赖）。因此
// cleanup 必须按逆序关闭，调用方只需要调用 Core.Stop。
type Core struct {
	cfg           *config.ClientConfig
	Client        *client.Client
	SocksServer   *proxy.Socks5Server
	HTTPServer    *proxy.HTTPProxyServer
	StreamHandler *proxy.StreamHandler
	dnsServer     *dns.ForwardServer

	// dnsCache 由核心持有并与代理服务器共享：服务端域名的预解析（启动期与
	// 后台重试）与 DNS pinning 地址发布都直接作用于它，不再经过代理服务器。
	// socks_port = 0 时没有本地代理入口，因此它是 nil。
	dnsCache *dns.Cache
	// transport 是隧道传输层，借用自 Client（与 StreamHandler 持有的是同一个
	// 实例），随 Client.Close 释放——本类型不再单独关闭它。
	transport transport.Transport

	// vpn 是本节点的 VPN 栈（对端面 + 隧道客户端 + 访问侧注入面）；vpn.enabled
	// 为 false 时是 nil，此时整条 VPN 路径不存在：不监听、不启 goroutine。
	// 它由 SOCKS5 入口借用（作为分流面），因此必须在关闭代理入口之后才能关闭，
	// 见 cleanup 与 vpnStack.close。
	vpn *vpnStack

	// derpShim 是本进程内 tailcat 通往内嵌 DERP 的唯一出口（见 derpshim.go）。
	// 它必须在关闭 VPN 栈之后关闭：tailcat 在飞期间仍会经它拨 DERP。
	derpShim *derpShim

	// StartupWarn 保存初始化核心时检测到的非致命警告（例如自定义规则文件
	// 加载失败，或服务端域名暂时无法解析），调用方可以在不中断启动的情况下
	// 将其展示给用户。
	StartupWarn error

	// done 在 Stop（或 Run 失败的清理路径）关闭，既是"核心已停止"的信号，
	// 也是后台任务（服务端域名重试）的停止信号。doneOnce 保证只关闭一次。
	done     chan struct{}
	doneOnce sync.Once

	// stopOnce 使 Stop 幂等：调用方（托盘关闭流程、更新重启路径、headless
	// 退出路径）可能对同一个核心调用多次。Run 的错误清理路径直接调 cleanup，
	// 那时核心尚未外泄，因此不需要经过它。
	stopOnce sync.Once

	// domainReady 在服务端域名首次解析成功（或无需解析）时关闭；
	// domainReadyOnce 保证只关闭一次。启用 TUN 前必须先就绪：系统 DNS 被
	// 指向本机转发服务器后，解析服务端域名不能再依赖隧道本身。
	domainReady     chan struct{}
	domainReadyOnce sync.Once

	// retryCancel 取消进行中的后台域名解析尝试，由 retryMu 保护：
	// Stop 可能在重试 goroutine 正持有一次尝试时执行。
	retryMu     sync.Mutex
	retryCancel context.CancelFunc
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
		transport:     cli.Transport(),
		StartupWarn:   cli.StartupWarning(),
		done:          make(chan struct{}),
		domainReady:   make(chan struct{}),
	}

	// VPN 栈必须在本地代理入口之前建立：SOCKS5 服务器要把它作为分流面注入
	// （见 proxy.Socks5Options.VPN）。此后的任何失败路径都通过 c.cleanup() 收尾，
	// 因此它也会把已经建好的 VPN 一起拆掉。
	//
	// 失败在这里**不再中止启动**：VPN 是可选功能，配置写错或本机条件不满足
	// （例如 Android 上没有 ALL_PROXY 钩子、密钥目录不可写）都只应让 VPN 缺席，
	// 而不该把基础代理一起拖死（见 AGENTS.md 要点 13 的启动韧性）。
	var vpnRoute proxy.VPNRoute
	if cfg.VPN.Enabled {
		route, err := c.startVPNSession(cfg, streamHandler, method, timeouts)
		if err != nil {
			c.StartupWarn = errors.Join(c.StartupWarn, fmt.Errorf("vpn disabled for this session: %w", err))
			log.Error("[VPN] disabled for this session", "err", err)
		} else {
			vpnRoute = route
		}
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
			c.cleanup()
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
		dnsAddr = forwardDNSListenAddr()
		if err := prebindUDP(dnsAddr); err != nil {
			c.cleanup()
			return nil, forwardDNSListenError(dnsAddr, err)
		}
	}

	if socksAddr != "" {
		serverDomain := ""
		if svr := cfg.DefaultServer(); svr != nil && !util.IsIP(svr.Address) {
			serverDomain = svr.Address
		}
		// DNS 缓存由核心持有：服务端域名的预解析与 DNS pinning 地址发布是核心的
		// 启动编排，代理服务器只是这份缓存的又一个使用者。
		c.dnsCache = dns.NewCache(serverDomain)
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
			DNSCache:          c.dnsCache,
			// nil 时 VPN 分流完全关闭（本会话没有 vpn.enabled）。
			VPN: vpnRoute,
		})
		if err != nil {
			c.cleanup()
			return nil, err
		}
		c.SocksServer = socksServer
		log.Info("[EASYSS] starting socks5 server", "addr", socksAddr)
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
		// 静态名钩子只在 VPN 启用时存在：它把对端名字解析成 overlay IPv4。
		// 非 VPN 会话传 nil，转发服务器行为逐字节不变。
		//
		// 同一份注入也交给 SOCKS5 入口（Socks5Options.VPN 的可选静态名能力）：
		// TUN 模式下系统解析器写的是公网 DNS，查询经 tun2socks 到达代理的 DNS
		// 拦截器，那个前端才是 TUN 下真正被用到的路径；这里的转发服务器服务的是
		// enable_forward_dns 的 LAN 部署（见 docs/vpn-design.md 5.4）。
		var staticNames dns.StaticNames
		if c.vpn != nil {
			staticNames = c.vpn.route
		}
		c.dnsServer = dns.NewForwardServer(dnsAddr, cli.Router().ShouldIPV6Disable(), staticNames)
		log.Info("[EASYSS] starting dns forward server", "addr", dnsAddr)
		go func() {
			if err := c.dnsServer.Start(); err != nil {
				log.Error("[EASYSS] dns forward server", "err", err)
			}
		}()
	}

	// 服务端域名解析不再中止启动：开机自启动时网络常常尚未就绪（例如 WiFi
	// 还没初始化完），此时解析必然失败。进程照常启动并监听本地端口，后台按
	// 退避重试解析，网络恢复后自动补齐 DNS 缓存并使代理可用。
	if err := c.resolveServerDomain(cfg); err != nil {
		host := ""
		if svr := cfg.DefaultServer(); svr != nil {
			host = svr.Address
		}
		c.StartupWarn = errors.Join(c.StartupWarn,
			fmt.Errorf("%w: %s: %w", ErrServerDomainUnresolved, host, err))
		// 依赖与调参在这里（调用方 goroutine 上）捕获，见 serverDomainRetry。
		go c.retryServerDomain(cfg, serverDomainRetry{
			prePopulate: prePopulateServerDomain,
			reset:       resetResolveState,
			dnsServers:  config.DirectDNSServers,
			requireIPv4: cfg.Routing.IPV6Rule != "enable",
			timeout:     serverStartupResolveTimeout,
			base:        serverDomainRetryBase,
			max:         serverDomainRetryMax,
		})
	} else {
		c.markServerDomainReady()
	}

	log.Info("[EASYSS] started successfully", "elapsed_ms", time.Since(start).Milliseconds())
	// 开启一个全新的统计会话：进程可能经历多次启动/停止周期（例如
	// Android），因此同时重置会话开始时间和所有计数器。
	stats.ResetStartTime()
	stats.ResetCounters()
	stats.StartSpeedMonitor()
	return c, nil
}

// Stop 停止核心并释放它持有的一切。它幂等：同一核心被重复停止（例如托盘的
// 关闭流程与更新重启路径各调一次）不会二次拆除服务器——那会让 SOCKS5 的
// accept 探测白等一次并留下后台补关闭 goroutine（见 stopOnce）。
func (c *Core) Stop() {
	c.stopOnce.Do(func() {
		c.cleanup()
		log.Info("[EASYSS] stopped")
	})
}

// resolveServerDomain 通过直连 DNS 服务器（带系统 DNS 兜底）预先解析代理
// 服务器主机名并预填充 DNS 缓存，使代理路径永远不会等待冷查询；这次预填充
// 同时也是 TUN 模式的安全前提（系统 DNS 指向本机转发服务器后，解析服务端
// 域名不能再依赖隧道本身）。
//
// 它只做一次有界尝试：失败以错误返回，是否致命由调用方决定（见 Run：失败
// 降级为启动警告并转入后台重试）。字面 IP 地址、没有默认服务器、或没有本地
// socks5 服务时无需解析，直接返回 nil。
func (c *Core) resolveServerDomain(cfg *config.ClientConfig) error {
	svr := cfg.DefaultServer()
	if svr == nil || util.IsIP(svr.Address) {
		return nil
	}
	// 没有本地代理入口时没有需要预填充的 DNS 缓存。
	if c.dnsCache == nil {
		return nil
	}
	if len(config.DirectDNSServers) == 0 {
		return errors.New("no direct dns servers configured")
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), serverStartupResolveTimeout)
	defer cancel()

	err := prePopulateServerDomain(c.dnsCache, ctx, svr.Address, config.DirectDNSServers,
		cfg.Routing.IPV6Rule != "enable")
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
		"ips", c.publishServerIPs(),
	)
	return nil
}

// publishServerIPs 把预解析得到的服务端地址交给客户端，使传输层拨号做 DNS
// pinning（见 client.Client.SetServerIPs）：这样即使操作系统解析器坏掉或被
// 污染（例如家用路由器的 DNS 返回畸形应答），隧道依然能连上服务端。返回交出去
// 的地址，便于调用方记录日志。
func (c *Core) publishServerIPs() []string {
	if c.Client == nil || c.dnsCache == nil {
		return nil
	}
	ips := c.dnsCache.ServerAddrs()
	c.Client.SetServerIPs(ips)
	return ips
}

// PrePopulateServerDomain 用给定域名的解析结果 IP 预先填充 DNS 缓存：依次尝试
// 给定的各个 DNS 服务器，全部失败时回退到系统 DNS 服务器。TUN 启用路径在把系统
// DNS 指向本机转发服务器之前调用它，避免解析服务端域名时形成循环依赖。
//
// ctx 约束整个解析过程，使不可达的 DNS 服务器无法阻塞启动
// （参见 dns.Cache.PrePopulateWithFallback）。
func (c *Core) PrePopulateServerDomain(ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error {
	if c.dnsCache == nil {
		return errors.New("dns cache not available (socks_port is disabled)")
	}
	return c.dnsCache.PrePopulateWithFallback(ctx, domain, dnsServers, requireIPv4)
}

// serverDomainRetry 把后台重试所需的可注入依赖与调参在派发 goroutine 之前
// 捕获下来：prePopulateServerDomain/resetResolveState/serverDomainRetry*
// 都是测试在两次派发之间会替换的包级变量，从后台 goroutine 里读取它们会与
// 下一个测试产生数据竞争。
type serverDomainRetry struct {
	prePopulate func(cache *dns.Cache, ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error
	reset       func()
	dnsServers  []string
	requireIPv4 bool
	timeout     time.Duration
	base        time.Duration
	max         time.Duration
}

// retryServerDomain 在后台按指数退避重试服务端域名解析，直到成功或核心停止，
// 成功后关闭就绪通道。
//
// 它存在的唯一原因是开机自启动：进程常常先于网络就绪启动，此时解析必然失败，
// 但网络恢复后代理应当自动可用。每次尝试前调用 r.reset 清除 DNS 层的熔断状态
// 与系统 DNS 发现缓存——开机时的失败会把内置 DNS 服务器熔断 3 分钟
// （builtinDNSCoolDown），并把空的系统 DNS 列表缓存 5 分钟（systemDNSCacheTTL），
// 不清理会让"网络已恢复"被拖后数分钟。
func (c *Core) retryServerDomain(cfg *config.ClientConfig, r serverDomainRetry) {
	svr := cfg.DefaultServer()
	if svr == nil {
		// 没有默认服务器时无需解析：Run 的可就绪判定与这里保持一致。
		c.markServerDomainReady()
		return
	}

	delay := r.base
	for attempt := 1; ; attempt++ {
		select {
		case <-c.done:
			return
		case <-time.After(jitterDuration(delay)):
		}
		// 退避结束后再确认一次停止信号，避免在停止过程中新起一次解析。
		if c.stopped() {
			return
		}

		r.reset()

		ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
		c.setRetryCancel(cancel)
		err := r.prePopulate(c.dnsCache, ctx, svr.Address, r.dnsServers, r.requireIPv4)
		cancel()
		c.clearRetryCancel()

		if err == nil {
			log.Info("[EASYSS] server domain resolved by background retry",
				"host", svr.Address,
				"attempts", attempt,
				"ips", c.publishServerIPs(),
			)
			c.markServerDomainReady()
			return
		}
		// 首次失败已在 resolveServerDomain 里以 Warn 记录；后续尝试走 Debug，
		// 使长时间离线不会刷爆日志。
		log.Debug("[EASYSS] server domain retry failed",
			"host", svr.Address, "attempt", attempt, "err", err)

		if delay = min(delay*2, r.max); delay < r.base {
			delay = r.base
		}
	}
}

// jitterDuration 在 [0.8d, 1.2d) 内抖动退避间隔，避免大量客户端在同一时刻
// 开机时形成同步的解析请求突发。
func jitterDuration(d time.Duration) time.Duration {
	jittered := time.Duration(float64(d) * (0.8 + rand.Float64()*0.4))
	if jittered <= 0 {
		return d
	}
	return jittered
}

// setRetryCancel 记录进行中的后台解析尝试的取消函数。
func (c *Core) setRetryCancel(cancel context.CancelFunc) {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()
	c.retryCancel = cancel
}

// clearRetryCancel 丢弃已结束的后台解析尝试的取消函数。
func (c *Core) clearRetryCancel() {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()
	c.retryCancel = nil
}

// cancelRetry 取消进行中的后台解析尝试（若有）。可重复调用。
func (c *Core) cancelRetry() {
	c.retryMu.Lock()
	cancel := c.retryCancel
	c.retryCancel = nil
	c.retryMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// stopped 报告核心是否已停止。零值核心（done 为 nil）视为未停止。
func (c *Core) stopped() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// closeDone 关闭"核心已停止"信号，幂等。
func (c *Core) closeDone() {
	if c == nil || c.done == nil {
		return
	}
	c.doneOnce.Do(func() { close(c.done) })
}

// markServerDomainReady 记录服务端域名已就绪（解析成功或无需解析），幂等。
// 零值核心（domainReady 为 nil）上是空操作。
func (c *Core) markServerDomainReady() {
	if c == nil || c.domainReady == nil {
		return
	}
	c.domainReadyOnce.Do(func() { close(c.domainReady) })
}

// ServerDomainReady 返回在服务端域名首次解析成功（或无需解析）时关闭的通道。
// 调用方（启动路径、托盘）用它判断"现在可以安全启用 TUN"。
// 零值核心上返回 nil；调用方应把 nil 视为"无需等待"。
func (c *Core) ServerDomainReady() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.domainReady
}

// Done 返回核心停止时关闭的通道。零值核心上返回 nil。
func (c *Core) Done() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.done
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

// forwardDNSListenAddr 返回 forward DNS 服务器的监听地址。它刻意监听所有
// 网卡的 53 端口：该功能面向"把 easyss 部署在路由器/软路由上、LAN 设备的
// DNS 指向这台路由器"的场景，只监听回环时 LAN 设备根本够不到（见 README
// 的透明代理章节）。通配地址在支持双栈的平台上同时接受 IPv4 与 IPv6 查询，
// 应答的源地址由内核按客户端所在网段选取，因此多网口路由器无需额外配置。
func forwardDNSListenAddr() string {
	return ":53"
}

// forwardDNSListenError 包装 forward DNS 的监听失败。53 端口被占用是这个
// 功能最常见的启动失败原因（路由器上通常是 dnsmasq 或 systemd-resolved 先
// 占着），裸的 bind 错误无法让用户知道下一步该做什么，因此把排查方向直接
// 写进错误信息。
func forwardDNSListenError(addr string, err error) error {
	return fmt.Errorf("dns forward server listen %s: %w (端口 53 常被 dnsmasq 或 "+
		"systemd-resolved 占用，请先停用它们的 DNS 监听再启用 enable_forward_dns)", addr, err)
}

// cleanup 撤销核心持有的一切：先取消后台解析尝试并关闭停止信号（让后台
// goroutine 在资源被拆除前退出），再按"启动顺序的逆序"关闭各组件。
//
// 逆序是硬约束，不是风格问题：
//   - HTTP 代理入口依赖本地 SOCKS5 入口（它的反向代理连接池与回退路径都拨
//     SocksAddr），因此必须比 SOCKS5 先关，否则正在收尾的请求会打到一个
//     已经关闭的入口；
//   - 传输层（client.Client）被上面所有入口借用（StreamHandler 持有它），
//     必须最后关：Socks5Server.Close 只关监听器与 UDP 会话，在飞中继正是靠
//     传输层关闭才结束的（见 client/proxy.Socks5Server.Close）。
func (c *Core) cleanup() {
	c.cancelRetry()
	c.closeDone()

	if c.dnsServer != nil {
		_ = c.dnsServer.Shutdown()
	}
	if c.HTTPServer != nil {
		_ = c.HTTPServer.Close()
	}
	if c.SocksServer != nil {
		_ = c.SocksServer.Close()
	}
	// VPN 在代理入口之后关闭：Socks5Server 借用它作为分流面，反过来会让在飞的
	// 隧道拨号打到一个已关闭的客户端集合（见 vpnStack.close）。
	c.StopVPN()
	// DERP 入口最后关：tailcat 在 VPN 栈关闭的过程中仍可能在飞地经它拨 DERP。
	if c.derpShim != nil {
		c.derpShim.close()
		c.derpShim = nil
	}
	if c.Client != nil {
		_ = c.Client.Close()
	}
	// 不再有活跃会话，因此也不再需要会话开始时间。
	stats.ClearStartTime()
	stats.StopSpeedMonitor()
}
