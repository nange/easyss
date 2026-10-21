package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/libp2p/go-netroute"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/transport"
	"github.com/nange/easyss/v3/transport/http2"
	"github.com/nange/easyss/v3/util"
	"github.com/xjasonlyu/tun2socks/v2/dialer"
)

type Client struct {
	// cfg 是本会话的配置快照，client.New 之后只读：调用方用 copy-on-write 发布新快照。
	cfg           *config.ClientConfig
	router        *router.Router
	transport     transport.Transport
	masterKey     []byte
	dialer        atomic.Pointer[dialer.Dialer]
	bound         atomic.Value // boundIface：直连拨号器当前绑定的接口
	closeIdleDone chan struct{}
	closeOnce     sync.Once
	closed        atomic.Bool

	// tunMode 是"本会话的 TUN 是否生效"：直连拨号路径会反复读它，不能放进配置快照。
	tunMode atomic.Bool

	// serverDomain 是服务端域名（字面 IP 时为空）；serverIPs 是 runner 预解析后注入的地址，
	// dialWithConfig 优先拨它们，系统 DNS 坏掉或被污染时也能连上。
	serverDomain string
	serverIPs    atomic.Pointer[[]string]

	fileWarn error

	mu sync.RWMutex

	// sys 是直连拨号的系统依赖；零值回落到生产实现。
	sys sysDeps
}

type boundIface struct {
	name  string
	index int
}

// 探测目标取 0.0.0.1 而非公网地址：TUN 的路由从 1.0.0.0/8 起，该网段永远路由到物理
// 接口，绑到 TUN 设备会形成环路。
func detectDefaultIface() (*net.Interface, error) {
	iface, _, err := util.SysDefaultRoute()
	if err != nil {
		iface, err = probeDialIface()
	}
	if err != nil {
		return nil, err
	}
	if iface == nil {
		return nil, errors.New("no interface for default route")
	}
	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("default interface %s is down", iface.Name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("read addresses of %s: %w", iface.Name, err)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.IsGlobalUnicast() {
			return iface, nil
		}
	}
	return nil, fmt.Errorf("default interface %s has no global unicast address", iface.Name)
}

// 改读路由表：Windows 拒绝 0.0.0.0/8 目标，拨不出去。
func probeDialIface() (*net.Interface, error) {
	r, err := netroute.New()
	if err != nil {
		return nil, err
	}
	iface, _, _, err := r.Route(net.IPv4(0, 0, 0, 1))
	if err != nil {
		return nil, err
	}
	if iface == nil {
		return nil, errors.New("no interface for default route")
	}
	return iface, nil
}

func tunDeviceNameFromConfig(raw json.RawMessage) string {
	cfg, err := config.ParseTunConfig(raw)
	if err != nil {
		// 加载期已按同一形状校验，这里出错只可能是内存里的配置被直接改写。
		log.Warn("[CLIENT] parse local.tun_config", "err", err)
		return ""
	}
	return cfg.Device
}

// 直连拨号器绝不能绑定 easyss TUN 设备：包会被 tun2socks 捕获转发回本地代理，
// 代理拨号又进 TUN，形成无限请求循环。
func (c *Client) isTunIface(iface *net.Interface) bool {
	if util.IsTunIface(iface) {
		return true
	}
	if iface == nil || c.cfg == nil {
		return false
	}
	name := tunDeviceNameFromConfig(c.cfg.Local.TunConfig)
	return name != "" && iface.Name == name
}

// sysDeps 是直连拨号的系统依赖：接口探测、地址读取与绑定拨号。字段为 nil 时回落到
// 生产实现，零值 Client 因此也可用；测试只覆盖自己需要的那几项。
type sysDeps struct {
	detectIface     func() (*net.Interface, error)
	listInterfaces  func() ([]net.Interface, error)
	ifaceAddrs      func(*net.Interface) ([]net.Addr, error)
	bindUnsupported func() bool
	dialBound       func(*Client, context.Context, string, string) (net.Conn, error)
}

func (s sysDeps) iface() (*net.Interface, error) {
	if s.detectIface == nil {
		return detectDefaultIface()
	}
	return s.detectIface()
}

func (s sysDeps) interfaces() ([]net.Interface, error) {
	if s.listInterfaces == nil {
		return net.Interfaces()
	}
	return s.listInterfaces()
}

func (s sysDeps) addrs(iface *net.Interface) ([]net.Addr, error) {
	if s.ifaceAddrs == nil {
		return iface.Addrs()
	}
	return s.ifaceAddrs(iface)
}

func (s sysDeps) unbindable() bool {
	if s.bindUnsupported == nil {
		return util.SysDirectIfaceBindUnsupported()
	}
	return s.bindUnsupported()
}

func (s sysDeps) dial(c *Client, ctx context.Context, network, addr string) (net.Conn, error) {
	if s.dialBound == nil {
		return c.dialer.Load().DialContext(ctx, network, addr)
	}
	return s.dialBound(c, ctx, network, addr)
}

// android 上接口绑定不可用，此时返回空名称。
func (c *Client) initDirectDialer() string {
	if c.sys.unbindable() {
		c.dialer.Store(dialer.New())
		return ""
	}
	iface := c.startupDialIface()
	if iface == nil {
		log.Warn("[CLIENT] no physical interface found for direct dialer, using unbound dialer")
		c.dialer.Store(dialer.New())
		return ""
	}
	c.dialer.Store(dialer.New(dialer.WithBindToInterface(iface)))
	c.bound.Store(boundIface{name: iface.Name, index: iface.Index})
	return iface.Name
}

// 优先路由探测，但拒绝 easyss TUN 设备（崩溃的 TUN 会话可能留下把它重定向过去的陈旧路由）。
func (c *Client) startupDialIface() *net.Interface {
	iface, err := c.sys.iface()
	if err == nil && iface != nil && !c.isTunIface(iface) {
		return iface
	}
	if err != nil {
		log.Warn("[CLIENT] detect default interface failed", "err", err)
	} else if iface != nil {
		log.Warn("[CLIENT] detected easyss TUN device as default interface, falling back to interface enumeration", "iface", iface.Name)
	}

	ifaces, err := c.sys.interfaces()
	if err != nil {
		log.Warn("[CLIENT] list interfaces failed", "err", err)
		return nil
	}
	for i := range ifaces {
		iface := &ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || c.isTunIface(iface) {
			continue
		}
		addrs, err := c.sys.addrs(iface)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.IsGlobalUnicast() {
				log.Warn("[CLIENT] using fallback interface for direct dialer", "iface", iface.Name, "index", iface.Index)
				return iface
			}
		}
	}
	return nil
}

// 限定"拨某个预解析字面地址"的单次尝试：地址可能已被黑洞，剩余预算要留给域名回退。
const serverIPDialTimeout = 5 * time.Second

func New(cfg *config.ClientConfig) (*Client, error) {
	start := time.Now()

	masterKey, err := crypto.DeriveMasterKey(cfg.DefaultServer().Password)
	if err != nil {
		return nil, err
	}

	rt, err := router.New(router.Config{
		ProxyRule:  router.ParseProxyRule(cfg.Routing.ProxyRule),
		IPV6Rule:   router.ParseIPV6Rule(cfg.Routing.IPV6Rule),
		DirectFile: cfg.Routing.DirectFile,
		ProxyFile:  cfg.Routing.ProxyFile,
	})
	if err != nil {
		return nil, err
	}

	serverIPV6 := ""
	ipv6Networking := false
	if router.ParseIPV6Rule(cfg.Routing.IPV6Rule) != router.IPV6RuleDisable {
		// 约束整个解析过程（内置 + 系统 DNS 回退），不可达的 DNS 不能把启动拖住。
		ctx, cancel := context.WithTimeout(context.Background(), dns.PreResolveTimeout)
		serverIPV6 = resolveServerIPV6(ctx, cfg)
		cancel()
		ipv6Networking = detectIPV6Networking()
		log.Info("[CLIENT] server ipv6 resolved",
			"ipv6_rule", cfg.Routing.IPV6Rule,
			"server_ipv6", serverIPV6,
			"elapsed_ms", time.Since(start).Milliseconds(),
		)
	}
	rt.SetIPV6Info(ipv6Networking, serverIPV6)

	log.Info("[CLIENT] router initialized",
		"proxy_rule", cfg.Routing.ProxyRule,
		"ipv6_rule", cfg.Routing.IPV6Rule,
		"ipv6_networking", ipv6Networking,
		"server_ipv6", serverIPV6,
		"elapsed_ms", time.Since(start).Milliseconds(),
	)

	tlsCfg := cfg.UTLSConfig()

	serverDomain := cfg.DefaultServer().Host
	if util.IsIP(serverDomain) {
		serverDomain = ""
	}

	client := &Client{
		cfg:           cfg,
		router:        rt,
		masterKey:     masterKey,
		serverDomain:  serverDomain,
		fileWarn:      rt.CustomFileError(),
		closeIdleDone: make(chan struct{}),
	}
	client.bound.Store(boundIface{})
	// 用配置初值播种 TUN 状态：mobile 直接调用 runner.Run，没有托盘开关调 SetTunMode。
	client.SetTunMode(cfg.Local.EnableTun2socks)

	directIface := client.initDirectDialer()

	probeToken, err := crypto.ProbeToken(masterKey)
	if err != nil {
		return nil, fmt.Errorf("probe token: %w", err)
	}

	tr, err := http2.New(http2.Config{
		ServerURL:         cfg.ServerURL(),
		TLSConfig:         tlsCfg,
		MaxSlotCount:      cfg.Transport.ConnCountMax,
		StreamThreshold:   cfg.Transport.StreamThreshold,
		PrioritySlotRatio: cfg.Transport.PrioritySlotRatio,
		Timeouts:          sharedconfig.NewTimeouts(cfg.TimeoutDuration()),
		ConnMaxBytes:      cfg.Transport.ConnMaxBytes,
		ProbeToken:        probeToken,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return client.dialWithConfig(ctx, network, addr)
		},
	})
	if err != nil {
		return nil, err
	}

	client.transport = tr

	log.Info("[CLIENT] transport initialized", "server_url", cfg.ServerURL(), "max_slots", cfg.Transport.ConnCountMax, "stream_threshold", cfg.Transport.StreamThreshold, "server_addr", cfg.DefaultServerAddr(), "direct_iface", directIface, "elapsed_ms", time.Since(start).Milliseconds())

	go client.closeIdleLoop()
	go client.dialerRefreshLoop()

	return client, nil
}

// 有预解析地址时优先拨字面 IP（DNS pinning），TLS 校验仍用原域名；TUN 模式走绑定接口的拨号器。
func (c *Client) dialWithConfig(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.router.ShouldIPV6Disable() {
		switch network {
		case "tcp":
			network = "tcp4"
		case "udp":
			network = "udp4"
		}
	}

	if host, port, err := net.SplitHostPort(addr); err == nil {
		if ips := c.serverDialIPs(host); len(ips) > 0 {
			// 给域名回退预留一次机会：pin 阶段可能包含多个被黑洞的字面地址，不能吃掉整个拨号
			// 预算，否则回退会复用同一个已过期的 context 在毫秒内全部失败。
			pinnedCtx, cancelPinned := withDomainFallbackReserve(ctx)
			conn, err := c.dialServerIPs(pinnedCtx, network, ips, port)
			cancelPinned()
			if err == nil {
				return conn, nil
			}
			// 只把本次拨号回退给系统解析器，预解析结果保留：一次失败可能只是瞬态，丢掉它会让
			// 进程此后只能依赖系统解析器，而 pinning 的意义正是系统 DNS 不可靠时仍能连上。
			log.Warn("[CLIENT] dial server by pre-resolved ip failed, falling back to system resolver",
				"server", host, "ips", ips, "err", err)
		}
	}

	return c.dialAddr(ctx, network, addr)
}

// 把字面 IP 阶段的截止时间提前一个 serverIPDialTimeout，全部拨失败后域名回退还有预算。
func withDomainFallbackReserve(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}
	}
	pinnedDeadline := deadline.Add(-serverIPDialTimeout)
	if !time.Now().Before(pinnedDeadline) {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, pinnedDeadline)
}

// 仅当 host 正是服务端域名时返回字面 IP；规则禁用 IPv6 时过滤掉 IPv6 地址。
func (c *Client) serverDialIPs(host string) []string {
	if c.serverDomain == "" || !strings.EqualFold(host, c.serverDomain) {
		return nil
	}
	p := c.serverIPs.Load()
	if p == nil {
		return nil
	}
	var ips []string
	for _, ip := range *p {
		if c.router.ShouldIPV6Disable() && util.IsIPV6(ip) {
			continue
		}
		ips = append(ips, ip)
	}
	return ips
}

// 每个字面 IP 的尝试都有界；ctx 耗尽即停，把剩余时间留给域名回退。
func (c *Client) dialServerIPs(ctx context.Context, network string, ips []string, port string) (net.Conn, error) {
	var lastErr error
	for _, ip := range ips {
		if ctx.Err() != nil {
			// pin 阶段预算已耗尽：继续只会对剩下的地址各记一次根本没发生的拨号失败。
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			break
		}
		tryCtx, cancel := context.WithTimeout(ctx, serverIPDialTimeout)
		conn, err := c.dialAddr(tryCtx, network, net.JoinHostPort(ip, port))
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c *Client) dialAddr(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.tunModeEnabled() && c.dialer.Load() != nil {
		// 必须强制具体的 IP 版本，直连拨号器的 socket 绑定（IP_BOUND_IF）才生效：
		// 它只处理 "tcp4"/"udp4"/"tcp6"/"udp6"，不处理双栈的 "tcp"/"udp"。
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			if ip := net.ParseIP(host); ip != nil {
				if ip.To4() != nil {
					switch network {
					case "tcp":
						network = "tcp4"
					case "udp":
						network = "udp4"
					}
				} else {
					switch network {
					case "tcp":
						network = "tcp6"
					case "udp":
						network = "udp6"
					}
				}
			}
		}

		conn, err := c.sys.dial(c, ctx, network, addr)
		if err == nil || !isInterfaceStaleError(err) {
			return conn, err
		}

		// 绑定的接口过期了（休眠/唤醒、网络切换）：重建拨号器后重试一次。
		log.Warn("[CLIENT] direct dial failed, refreshing interface binding", "addr", addr, "err", err)
		if c.refreshDirectDialer() {
			return c.sys.dial(c, ctx, network, addr)
		}
		return conn, err
	}

	nd := &net.Dialer{
		KeepAlive: c.cfg.TimeoutDuration(),
	}
	return nd.DialContext(ctx, network, addr)
}

// 传空列表表示丢弃预解析地址，拨号随即回到系统解析器。
func (c *Client) SetServerIPs(ips []string) {
	if len(ips) == 0 {
		c.serverIPs.Store(nil)
		return
	}
	addrs := append([]string(nil), ips...)
	c.serverIPs.Store(&addrs)
}

// 绑定变更（名称或索引）时重建；检测失败保留现有拨号器，避免瞬态网络进一步降低连通性。
func (c *Client) refreshDirectDialer() bool {
	if c.sys.unbindable() {
		return false
	}
	iface, err := c.sys.iface()
	if err != nil {
		log.Warn("[CLIENT] refresh direct dialer: detect interface failed", "err", err)
		return false
	}
	if c.isTunIface(iface) {
		// 探测本不该解析到 easyss TUN 设备（0.0.0.1 在 TUN 路由之外），但陈旧路由可能把它
		// 重定向过去；绑上去会让每次拨号都回环进 TUN，因此保留先前的物理接口绑定。
		log.Warn("[CLIENT] refresh direct dialer: detected easyss TUN device, keeping previous binding",
			"iface", iface.Name, "index", iface.Index)
		return false
	}

	prev, _ := c.bound.Load().(boundIface)
	if prev.name == iface.Name && prev.index == iface.Index {
		return false
	}

	c.dialer.Store(dialer.New(dialer.WithBindToInterface(iface)))
	c.bound.Store(boundIface{name: iface.Name, index: iface.Index})
	log.Info("[CLIENT] direct dialer rebound",
		"iface", iface.Name, "index", iface.Index,
		"prev_iface", prev.name, "prev_index", prev.index)
	return true
}

// 仅在 TUN 模式激活时运行，否则绑定的拨号器不被使用；重新检测让绑定在休眠/网络切换后依然有效。
func (c *Client) dialerRefreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if c.tunModeEnabled() {
				c.refreshDirectDialer()
			}
		case <-c.closeIdleDone:
			return
		}
	}
}

func isInterfaceStaleError(err error) bool {
	if err == nil {
		return false
	}
	for _, e := range []error{
		syscall.ENETDOWN,
		syscall.ENODEV,
		syscall.ENETUNREACH,
		syscall.EHOSTUNREACH,
		syscall.EINVAL,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func resolveServerIPV6(ctx context.Context, cfg *config.ClientConfig) string {
	svr := cfg.DefaultServer()
	if svr == nil {
		return ""
	}
	if ip := net.ParseIP(svr.Host); ip != nil {
		if ip.To4() == nil {
			return svr.Host
		}
		return ""
	}

	// 惰性获取：判定只在熔断已置位时才调它，健康路径不必为每次解析付系统 DNS 发现的开销。
	hasFailover := func() bool { return len(dns.SystemDNSServers()) > 0 }
	route := dns.BuiltinRouteFor(hasFailover)
	if route == dns.BuiltinRouteRetry {
		log.Warn("[CLIENT] builtin dns breaker is armed but no system dns is available, retrying builtin servers",
			"server", svr.Host)
	}
	if route != dns.BuiltinRouteSkip {
		// 内置分支只能花掉总预算里除预留量以外的部分：黑洞内置 DNS（丢包而非立即拒绝）会把
		// 预算耗在一次查询上，系统 DNS 兜底复用同一个已过期的 ctx 就会在毫秒内全部失败。
		builtinCtx, cancelBuiltin := dns.WithSystemDNSFallbackReserve(ctx)
		defer cancelBuiltin()

		reachable := false
		for _, dnsServer := range config.DirectDNSServers {
			if builtinCtx.Err() != nil {
				log.Warn("[CLIENT] server ipv6 resolution budget exhausted, skipping remaining builtin dns servers",
					"server", svr.Host, "err", builtinCtx.Err())
				break
			}
			itemCtx, cancelItem := context.WithTimeout(builtinCtx, dns.ResolveItemTimeout)
			ips, err := dns.LookupIPV6FromContext(itemCtx, dnsServer, svr.Host)
			cancelItem()
			if err != nil {
				if ctx.Err() != nil {
					log.Warn("[CLIENT] server ipv6 resolution timed out", "server", svr.Host, "err", ctx.Err())
					return ""
				}
				continue
			}
			reachable = true
			dns.MarkBuiltinServerReachable(dnsServer)
			if len(ips) == 0 {
				continue
			}
			dns.MarkBuiltinDNSAvailable()
			return ips[0].String()
		}
		if !reachable {
			// 只有存在系统 DNS 兜底时才熔断：无兜底时熔断会让冷却期内连仍可用的
			// 内置服务器也跳过（Android 上系统 DNS 对应用不可见正是这种情形）。
			if hasFailover() {
				dns.MarkBuiltinDNSUnavailable()
			}
			log.Warn("[CLIENT] all builtin direct dns servers failed to resolve server ipv6, fallback to system dns", "server", svr.Host)
		}
	}

	for _, dnsServer := range dns.SystemDNSServers() {
		if ctx.Err() != nil {
			log.Warn("[CLIENT] server ipv6 resolution budget exhausted, skipping remaining system dns servers",
				"server", svr.Host, "err", ctx.Err())
			break
		}
		itemCtx, cancelItem := context.WithTimeout(ctx, dns.ResolveItemTimeout)
		ips, err := dns.LookupIPV6FromContext(itemCtx, dnsServer, svr.Host)
		cancelItem()
		if err == nil {
			dns.MarkSystemServerReachable(dnsServer)
		}
		if err != nil || len(ips) == 0 {
			if ctx.Err() != nil {
				log.Warn("[CLIENT] server ipv6 resolution timed out", "server", svr.Host, "err", ctx.Err())
				return ""
			}
			continue
		}
		return ips[0].String()
	}
	log.Warn("[CLIENT] failed to resolve server ipv6 via all direct and system dns servers", "server", svr.Host)
	return ""
}

func detectIPV6Networking() bool {
	_, _, err := util.SysGatewayAndDeviceV6()
	return err == nil
}

// 降级启动后启用 TUN 时若为空，平台脚本不会安装 IPv6 默认路由，IPv6 流量就会绕过隧道。
func (c *Client) RefreshServerIPV6() string {
	if c == nil {
		return ""
	}
	if ipv6 := c.router.ServerIPV6(); ipv6 != "" {
		return ipv6
	}
	if router.ParseIPV6Rule(c.cfg.Routing.IPV6Rule) == router.IPV6RuleDisable {
		return ""
	}
	if svr := c.cfg.DefaultServer(); svr == nil || net.ParseIP(svr.Host) != nil {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), dns.PreResolveTimeout)
	defer cancel()

	serverIPV6 := resolveServerIPV6(ctx, c.cfg)
	ipv6Networking := detectIPV6Networking()
	c.router.SetIPV6Info(ipv6Networking, serverIPV6)

	log.Info("[CLIENT] server ipv6 refreshed",
		"ipv6_rule", c.cfg.Routing.IPV6Rule,
		"server_ipv6", serverIPV6,
		"ipv6_networking", ipv6Networking,
	)
	return serverIPV6
}

func (c *Client) Router() *router.Router {
	return c.router
}

// 首个非致命警告（例如加载失败的自定义规则文件）；客户端仍用内置规则继续运行。
func (c *Client) StartupWarning() error {
	return c.fileWarn
}

func (c *Client) Transport() transport.Transport {
	return c.transport
}

func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return c.dialWithConfig(ctx, network, addr)
}

func (c *Client) MasterKey() []byte {
	return c.masterKey
}

func (c *Client) Config() *config.ClientConfig {
	return c.cfg
}

// 传输层无法重新打开，因此 Client 不能重启；调用方必须先关掉所有借用它的本地代理服务器。
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closeOnce.Do(func() { close(c.closeIdleDone) })
	if c.closed.Swap(true) {
		return nil
	}
	return c.transport.Close()
}

func (c *Client) closeIdleLoop() {
	ticker := time.NewTicker(8 * c.cfg.TimeoutDuration())
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.transport.CloseIdle()
		case <-c.closeIdleDone:
			return
		}
	}
}

// 只更新路由引擎，不回写 cfg：配置快照不可变，持久化由 App 用 copy-on-write 完成。
func (c *Client) SetProxyRule(rule string) {
	pr := router.ParseProxyRule(rule)
	c.router.SetProxyRule(pr)
}

// 直连拨号器据此决定是否走绑定接口的拨号路径；必须在引擎真正建立/拆除之后调用。
func (c *Client) SetTunMode(on bool) {
	c.tunMode.Store(on)
}

func (c *Client) tunModeEnabled() bool {
	return c.tunMode.Load()
}
