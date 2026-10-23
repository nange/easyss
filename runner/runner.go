package runner

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/nange/easyss/v3/client"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
	"github.com/nange/easyss/v3/util"
)

// ErrSocksRequired 表示启用了 HTTP 代理却没有启用 SOCKS5 入口。托盘用 errors.Is 识别它。
var ErrSocksRequired = errors.New("http proxy requires socks_port to be enabled")

// ErrServerDomainUnresolved 标记启动时服务端域名未能解析的非致命警告，调用方用
// errors.Is 识别并提示"网络可能尚未就绪"。
var ErrServerDomainUnresolved = errors.New("server domain unresolved")

// options 是一次 Run 的可注入依赖：解析策略、退避窗口与 forward DNS 监听地址。
// 生产路径用 defaultOptions，测试构造自己的实例即可，无需改动包级状态。
type options struct {
	// startupResolveTimeout 取 dns.PreResolveTimeout（预解析总预算的唯一事实来源，
	// client.New 与 TUN helper 共用）。
	startupResolveTimeout time.Duration
	retryBase             time.Duration
	retryMax              time.Duration
	prePopulate           func(cache *dns.Cache, ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error
	reset                 func()
	// forwardDNSListenAddr 刻意监听所有网卡的 53 端口：该功能面向"把 easyss 部署在
	// 路由器上、LAN 设备的 DNS 指向它"的场景，只监听回环时 LAN 设备够不到。
	forwardDNSListenAddr string
}

func defaultOptions() options {
	return options{
		startupResolveTimeout: dns.PreResolveTimeout,
		retryBase:             time.Second,
		retryMax:              15 * time.Second,
		prePopulate: func(cache *dns.Cache, ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error {
			return cache.PrePopulateWithFallback(ctx, domain, dnsServers, requireIPv4)
		},
		reset:                dns.ResetResolveState,
		forwardDNSListenAddr: ":53",
	}
}

// Core 持有一次客户端会话的全部组件，并唯一负责它们的关闭顺序。Client 是传输层与
// 路由引擎的所有者，其余服务器只借用它们，因此调用方只需 Core.Stop。
type Core struct {
	cfg           *clientconfig.ClientConfig
	Client        *client.Client
	SocksServer   *proxy.Socks5Server
	HTTPServer    *proxy.HTTPProxyServer
	StreamHandler *proxy.StreamHandler
	dnsServer     *dns.ForwardServer

	// 与代理服务器共享，DNS pinning 直接作用于它；socks_port = 0 时为 nil。
	dnsCache  *dns.Cache
	transport transport.Transport

	// vpn 是本会话的 VPN 栈（对端面 + 隧道客户端 + 访问侧注入面），vpn.enabled 为 false
	// 时是 nil。SOCKS5 入口借用它作为分流面，因此必须晚于代理入口关闭（见 cleanup）。
	vpn *vpnStack

	// ServerAddr 是本次会话**实际使用**的服务器（host:port），会话起点解析一次后不再回读
	// 配置的 default 标记：托盘切换、失败回滚与自更新重启都会改写那个标记。
	ServerAddr string

	// StartupWarn 保存初始化核心时检测到的非致命警告（例如自定义规则文件
	// 加载失败，或服务端域名暂时无法解析），调用方可以在不中断启动的情况下
	// 将其展示给用户。
	StartupWarn error

	// 既是"核心已停止"信号也是后台域名重试的停止信号。
	done     chan struct{}
	doneOnce sync.Once

	stopOnce sync.Once

	// 服务端域名首次解析成功（或无需解析）时关闭。启用 TUN 前必须先就绪：系统 DNS
	// 被指向本机转发服务器后，解析服务端域名不能再依赖隧道本身。
	domainReady     chan struct{}
	domainReadyOnce sync.Once

	// 取消进行中的后台解析尝试，受 retryMu 保护。
	retryMu     sync.Mutex
	retryCancel context.CancelFunc

	opts options
}

func Run(cfg *clientconfig.ClientConfig) (*Core, error) {
	return runWithOptions(cfg, defaultOptions())
}

func runWithOptions(cfg *clientconfig.ClientConfig, opts options) (*Core, error) {
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

	timeouts := config.NewTimeouts(cfg.TimeoutDuration())

	c := &Core{
		cfg:           cfg,
		Client:        cli,
		StreamHandler: proxy.NewStreamHandler(cli.Transport(), cli.MasterKey(), cfg.Shaper, timeouts),
		transport:     cli.Transport(),
		ServerAddr:    cfg.DefaultServer().HostPort(),
		StartupWarn:   cli.StartupWarning(),
		done:          make(chan struct{}),
		domainReady:   make(chan struct{}),
		opts:          opts,
	}

	// 清理只有一条路径：错误返回时先关闭尚未移交的监听器，再交给 c.cleanup。
	transferred := false
	var eps *localEndpoints
	defer func() {
		if transferred {
			return
		}
		eps.Close()
		c.cleanup()
	}()

	// 在派发任何服务器 goroutine 之前完成校验与监听绑定：监听失败（端口占用、
	// fd 耗尽）因此在 Run 返回前暴露，而不是让 UI 显示"已启动"而代理实际不可用。
	if err := validateLocalEndpoints(cfg); err != nil {
		return nil, err
	}
	eps, err = openLocalEndpoints(cfg, opts)
	if err != nil {
		return nil, err
	}

	// VPN 栈先于本地代理入口建立：SOCKS5 要把它作为分流面注入（见 Socks5Options.VPN）。
	// 失败只让本会话缺席 VPN，不中止启动；此后的错误返回由上面的 defer 交给 cleanup。
	var vpnRoute proxy.VPNRoute
	if cfg.VPN.Enabled {
		route, err := c.startVPNSession(cfg, c.StreamHandler, method, timeouts)
		if err != nil {
			c.StartupWarn = errors.Join(c.StartupWarn, fmt.Errorf("vpn disabled for this session: %w", err))
			log.Error("[VPN] disabled for this session", "err", err)
		} else {
			vpnRoute = route
		}
	}

	if err := c.buildLocalServers(cfg, eps, method, timeouts, vpnRoute); err != nil {
		return nil, err
	}

	c.serveLocal(eps)
	c.startDomainResolution(cfg, opts)

	log.Info("[EASYSS] started successfully", "elapsed_ms", time.Since(start).Milliseconds())
	stats.ResetStartTime()
	stats.ResetCounters()
	stats.StartSpeedMonitor()

	// 只有走到这里才移交所有权；任何提前的错误返回都由上面的 defer 清理。
	transferred = true
	return c, nil
}

// buildLocalServers 只构造服务器，不派发 goroutine；任何构造失败都在 Run 返回前暴露。
func (c *Core) buildLocalServers(cfg *clientconfig.ClientConfig, eps *localEndpoints, method protocol.Method,
	timeouts config.Timeouts, vpnRoute proxy.VPNRoute) error {
	if eps.socksLn != nil {
		serverDomain := ""
		if svr := cfg.DefaultServer(); svr != nil && !util.IsIP(svr.Host) {
			serverDomain = svr.Host
		}
		c.dnsCache = dns.NewCache(serverDomain)
		socksServer, err := proxy.NewSocks5Server(proxy.Socks5Options{
			ListenAddr:        eps.socksAddr,
			Username:          cfg.AuthUsername,
			Password:          cfg.AuthPassword,
			Handler:           c.StreamHandler,
			Router:            c.Client.Router(),
			ServerDomain:      serverDomain,
			Method:            method,
			DisableQUIC:       !cfg.Local.EnableQUIC,
			Timeouts:          timeouts,
			DirectDialContext: c.Client.DialContext,
			DNSCache:          c.dnsCache,
			// nil 时 VPN 分流完全关闭（本会话没有 vpn.enabled）。
			VPN: vpnRoute,
		})
		if err != nil {
			return err
		}
		c.SocksServer = socksServer
	}

	if eps.httpLn != nil {
		// SocksAddr 必须取自 util.LocalProxyDialAddr：bind_all 时它是同族回环 [::1]，
		// 自己拼 127.0.0.1 在只接受 IPv6 的平台上连不上。
		httpServer, err := proxy.NewHTTPProxyServer(proxy.HTTPProxyOptions{
			ListenAddr: eps.httpAddr,
			SocksAddr:  eps.socksDialAddr,
			Username:   cfg.AuthUsername,
			Password:   cfg.AuthPassword,
			Timeouts:   timeouts,
			Handler:    c.StreamHandler,
			Router:     c.Client.Router(),
			Method:     method,
			Dial:       c.Client.DialContext,
		})
		if err != nil {
			return err
		}
		c.HTTPServer = httpServer
		// 系统代理指向这个入口，但它不参与 VPN 分流（见 README 的"访问对端"）：不明说的话，
		// 用户看到的是"http://<peer>/ 能开、https://<peer>/ 打不开"，而默认配置下该入口总在运行。
		if vpnRoute != nil {
			log.Warn("[VPN] the HTTP proxy entry (the one the system proxy points at) does not route peer traffic; " +
				"reach peers through the SOCKS5 port or TUN")
		}
	}

	if eps.dnsPC != nil {
		// 静态名钩子只在 VPN 启用时存在：它把对端名字解析成 overlay IPv4，nil 时行为不变。
		var staticNames dns.StaticNames
		if c.vpn != nil {
			staticNames = c.vpn.route
		}
		c.dnsServer = dns.NewForwardServer(eps.dnsAddr, c.Client.Router().ShouldIPV6Disable(), staticNames)
	}

	return nil
}

// serveLocal 在所有服务器构造成功后才派发 goroutine，"Run 成功"因此意味着端口确实在监听。
func (c *Core) serveLocal(eps *localEndpoints) {
	if eps.socksLn != nil {
		log.Info("[EASYSS] starting socks5 server", "addr", eps.socksLn.Addr().String())
		go func() {
			if err := c.SocksServer.Serve(eps.socksLn); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Error("[EASYSS] socks5 server", "err", err)
			}
		}()
	}
	if eps.httpLn != nil {
		log.Info("[EASYSS] starting http proxy server", "addr", eps.httpLn.Addr().String())
		go func() {
			if err := c.HTTPServer.Serve(eps.httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("[EASYSS] http proxy server", "err", err)
			}
		}()
	}
	if eps.dnsPC != nil {
		log.Info("[EASYSS] starting dns forward server", "addr", eps.dnsPC.LocalAddr().String())
		go func() {
			if err := c.dnsServer.Serve(eps.dnsPC); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Error("[EASYSS] dns forward server", "err", err)
			}
		}()
	}
}

// startDomainResolution 只做一次有界预解析；失败降级为启动警告并在后台按退避重试。
func (c *Core) startDomainResolution(cfg *clientconfig.ClientConfig, opts options) {
	if err := c.resolveServerDomain(cfg); err != nil {
		host := ""
		if svr := cfg.DefaultServer(); svr != nil {
			host = svr.Host
		}
		c.StartupWarn = errors.Join(c.StartupWarn,
			fmt.Errorf("%w: %s: %w", ErrServerDomainUnresolved, host, err))
		go c.retryServerDomain(cfg, serverDomainRetry{
			prePopulate: opts.prePopulate,
			reset:       opts.reset,
			dnsServers:  clientconfig.DirectDNSServers,
			requireIPv4: cfg.Routing.IPV6Rule != "enable",
			timeout:     opts.startupResolveTimeout,
			base:        opts.retryBase,
			max:         opts.retryMax,
		})
		return
	}
	c.markServerDomainReady()
}

// Stop 幂等：重复拆除会让 SOCKS5 的 accept 探测白等一次并留下后台补关闭 goroutine。
func (c *Core) Stop() {
	c.stopOnce.Do(func() {
		c.cleanup()
		log.Info("[EASYSS] stopped")
	})
}

// resolveServerDomain 通过直连 DNS 预解析服务端主机名并预填充缓存。只做一次有界
// 尝试，是否致命由调用方决定。
func (c *Core) resolveServerDomain(cfg *clientconfig.ClientConfig) error {
	svr := cfg.DefaultServer()
	if svr == nil || util.IsIP(svr.Host) {
		return nil
	}
	if c.dnsCache == nil {
		return nil
	}
	if len(clientconfig.DirectDNSServers) == 0 {
		return errors.New("no direct dns servers configured")
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), c.opts.startupResolveTimeout)
	defer cancel()

	err := c.opts.prePopulate(c.dnsCache, ctx, svr.Host, clientconfig.DirectDNSServers,
		cfg.Routing.IPV6Rule != "enable")
	if err != nil {
		log.Warn("[EASYSS] server domain resolution failed at startup",
			"host", svr.Host,
			"elapsed_ms", time.Since(start).Milliseconds(),
			"err", err,
		)
		return fmt.Errorf("server domain %s resolution failed: %w", svr.Host, err)
	}
	log.Info("[EASYSS] server domain resolved at startup",
		"host", svr.Host,
		"elapsed_ms", time.Since(start).Milliseconds(),
		"ips", c.publishServerIPs(),
	)
	return nil
}

// publishServerIPs 把预解析得到的服务端地址交给客户端做 DNS pinning：系统解析器坏掉
// 或被污染时隧道仍能连上服务端。
func (c *Core) publishServerIPs() []string {
	if c.Client == nil || c.dnsCache == nil {
		return nil
	}
	ips := c.dnsCache.ServerAddrs()
	c.Client.SetServerIPs(ips)
	return ips
}

// PrePopulateServerDomain 用给定域名的解析结果预填充缓存，全部失败时回退系统 DNS。
// TUN 启用路径在把系统 DNS 指向本机之前调用它，避免解析服务端域名形成循环依赖。
func (c *Core) PrePopulateServerDomain(ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error {
	if c.dnsCache == nil {
		return errors.New("dns cache not available (socks_port is disabled)")
	}
	return c.dnsCache.PrePopulateWithFallback(ctx, domain, dnsServers, requireIPv4)
}

// serverDomainRetry 在派发 goroutine 之前捕获可注入的依赖与调参：这些包级变量会被测试
// 在两次派发之间替换，从后台 goroutine 里读会产生数据竞争。
type serverDomainRetry struct {
	prePopulate func(cache *dns.Cache, ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error
	reset       func()
	dnsServers  []string
	requireIPv4 bool
	timeout     time.Duration
	base        time.Duration
	max         time.Duration
}

// retryServerDomain 在后台按指数退避重试，直到成功或核心停止。每次尝试前调用 r.reset
// 清除内置 DNS 熔断与系统 DNS 发现缓存，否则"网络已恢复"会被拖后数分钟。
func (c *Core) retryServerDomain(cfg *clientconfig.ClientConfig, r serverDomainRetry) {
	svr := cfg.DefaultServer()
	if svr == nil {
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
		if c.stopped() {
			return
		}

		r.reset()

		ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
		c.setRetryCancel(cancel)
		err := r.prePopulate(c.dnsCache, ctx, svr.Host, r.dnsServers, r.requireIPv4)
		cancel()
		c.clearRetryCancel()

		if err == nil {
			log.Info("[EASYSS] server domain resolved by background retry",
				"host", svr.Host,
				"attempts", attempt,
				"ips", c.publishServerIPs(),
			)
			c.markServerDomainReady()
			return
		}
		// 首次失败已由 resolveServerDomain 以 Warn 记录，这里走 Debug 以免离线时刷爆日志。
		log.Debug("[EASYSS] server domain retry failed",
			"host", svr.Host, "attempt", attempt, "err", err)

		if delay = min(delay*2, r.max); delay < r.base {
			delay = r.base
		}
	}
}

// jitterDuration 在 [0.8d, 1.2d) 内抖动退避间隔，避免大量客户端开机时同步解析。
func jitterDuration(d time.Duration) time.Duration {
	jittered := time.Duration(float64(d) * (0.8 + rand.Float64()*0.4))
	if jittered <= 0 {
		return d
	}
	return jittered
}

func (c *Core) setRetryCancel(cancel context.CancelFunc) {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()
	c.retryCancel = cancel
}

func (c *Core) clearRetryCancel() {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()
	c.retryCancel = nil
}

func (c *Core) cancelRetry() {
	c.retryMu.Lock()
	cancel := c.retryCancel
	c.retryCancel = nil
	c.retryMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

func (c *Core) stopped() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *Core) closeDone() {
	if c == nil || c.done == nil {
		return
	}
	c.doneOnce.Do(func() { close(c.done) })
}

func (c *Core) markServerDomainReady() {
	if c == nil || c.domainReady == nil {
		return
	}
	c.domainReadyOnce.Do(func() { close(c.domainReady) })
}

func (c *Core) ServerDomainReady() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.domainReady
}

func (c *Core) Done() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.done
}

// forwardDNSListenError 把排查方向写进错误信息：53 端口常被 dnsmasq 或
// systemd-resolved 占用。
func forwardDNSListenError(addr string, err error) error {
	return fmt.Errorf("dns forward server listen %s: %w (端口 53 常被 dnsmasq 或 "+
		"systemd-resolved 占用，请先停用它们的 DNS 监听再启用 enable_forward_dns)", addr, err)
}

// cleanup 按启动顺序的逆序关闭各组件：HTTP 入口反向代理拨 SocksAddr，必须比 SOCKS5
// 先关；传输层被所有入口借用，必须最后关。
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
	if c.Client != nil {
		_ = c.Client.Close()
	}
	stats.ClearStartTime()
	stats.StopSpeedMonitor()
}
