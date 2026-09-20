package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/libp2p/go-netroute"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/transport"
	"github.com/nange/easyss/v3/transport/http2"
	"github.com/nange/easyss/v3/util"
	"github.com/xjasonlyu/tun2socks/v2/dialer"
)

type Client struct {
	cfg           *config.ClientConfig
	router        *router.Router
	transport     transport.Transport
	masterKey     []byte
	dialer        atomic.Pointer[dialer.Dialer]
	bound         atomic.Value // boundIface：直连拨号器当前绑定的接口
	closeIdleDone chan struct{}
	closeOnce     sync.Once

	// fileWarn 记录加载自定义直连/代理规则文件时出现的非致命错误，
	// 以启动警告的形式呈现（参见 StartupWarning）。
	// 客户端仍会使用内置规则继续运行。
	fileWarn error

	mu sync.RWMutex
}

// boundIface 记录直连拨号器当前绑定的接口，
// 以便刷新循环检测到变更（名称或索引）时重建拨号器。
type boundIface struct {
	name  string
	index int
}

// detectDialIface 返回 TUN 模式下直连拨号应绑定的接口：物理默认路由接口。
// 在 Windows 上，它从路由表读取 0.0.0.0/0 默认路由（跳过 easyss TUN
// 设备——TUN 激活时该设备拥有自己的默认路由）。在 darwin 和 linux 上，
// 它探测 0.0.0.1，该地址不会被 easyss TUN 路由（所有平台均从 1.0.0.0/8
// 开始）覆盖，因此即使在 TUN 路由激活时，查找结果也是物理默认接口——
// 绑定到 easyss TUN 设备本身会造成路由环路。Windows 无法使用该探测：
// 其路由查找会直接拒绝 0.0.0.0/8 目标。可在测试中覆盖。
var detectDialIface = func() (*net.Interface, error) {
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

// probeDialIface 通过探测 0.0.0.0/8 中的目标来查找默认路由接口，
// 该网段不会被 easyss TUN 路由（所有平台均从 1.0.0.0/8 开始）覆盖。
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

// tunDeviceNameFromConfig 从原始 tun_config JSON 中返回 TUN 设备名
// （如果存在）。设备名用于识别 easyss TUN 接口，使直连拨号器绝不绑定到它。
func tunDeviceNameFromConfig(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var cfg struct {
		Device string `json:"device"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return ""
	}
	return cfg.Device
}

// isTunIface 报告 iface 是否为 easyss TUN 设备。直连拨号器绝不能绑定到它：
// 发往 TUN 设备的数据包会被 tun2socks 捕获并转发回本地代理，代理的拨号
// 又会重新进入 TUN 设备——形成无限请求循环。
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

// listInterfaces 枚举系统接口。它是包级变量，
// 以便测试注入确定性的接口集合。
var listInterfaces = net.Interfaces

// ifaceAddrs 返回 iface 的地址。它是包级变量，
// 以便测试为合成接口注入确定性的地址。
var ifaceAddrs = func(iface *net.Interface) ([]net.Addr, error) { return iface.Addrs() }

// ifaceBindUnsupported 报告平台是否无法将直连拨号器绑定到接口
// （参见 util.SysDirectIfaceBindUnsupported）。它是包级变量，
// 以便测试确定性地覆盖平台分支。
var ifaceBindUnsupported = util.SysDirectIfaceBindUnsupported

// initDirectDialer 将直连拨号器存入 c.dialer，并返回所绑定物理接口的
// 名称（未绑定时返回 ""）。在接口绑定不受支持的平台上（android：
// netlink 被阻止，VpnService 只将选中的应用路由进 TUN），拨号器保持
// 未绑定状态，且不执行任何检测或告警。
func (c *Client) initDirectDialer() string {
	if ifaceBindUnsupported() {
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

// startupDialIface 确定直连拨号器在启动时绑定的接口。它优先使用路由探测，
// 但会拒绝 easyss TUN 设备（例如崩溃的 TUN 会话遗留的路由把探测重定向到
// 它时），并回退到枚举物理接口。没有合适的接口时返回 nil，此时使用未绑定
// 的拨号器。在接口绑定不受支持的平台上（android），initDirectDialer
// 不会调用本函数——拨号器保持未绑定（参见
// util.SysDirectIfaceBindUnsupported）。
func (c *Client) startupDialIface() *net.Interface {
	iface, err := detectDialIface()
	if err == nil && iface != nil && !c.isTunIface(iface) {
		return iface
	}
	if err != nil {
		log.Warn("[CLIENT] detect default interface failed", "err", err)
	} else if iface != nil {
		log.Warn("[CLIENT] detected easyss TUN device as default interface, falling back to interface enumeration", "iface", iface.Name)
	}

	ifaces, err := listInterfaces()
	if err != nil {
		log.Warn("[CLIENT] list interfaces failed", "err", err)
		return nil
	}
	for i := range ifaces {
		iface := &ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || c.isTunIface(iface) {
			continue
		}
		addrs, err := ifaceAddrs(iface)
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

// boundDialContext 通过绑定接口的直连拨号器拨号。它是包级变量，
// 以便测试确定性地注入失败。
var boundDialContext = func(c *Client, ctx context.Context, network, addr string) (net.Conn, error) {
	return c.dialer.Load().DialContext(ctx, network, addr)
}

// serverIPV6ResolveTimeout 约束 client.New 中同步的服务器 IPv6 解析。
// 解析服务器的 AAAA 记录需要对直连 DNS 服务器做 DNS 往返；在那些服务器
// 不可达的网络中，每个查询 5 秒的超时（乘以服务器数量）会让代理启动
// 每次都停滞数秒（在移动端最明显——VPN 不能在代理就绪之前上线）。
// 3s 对健康网络足够，并把最坏情况控制在很短；超时时路由引擎只是把
// IPv6 视为不可用（自动模式的保险默认）。可在测试中覆盖。
var serverIPV6ResolveTimeout = 3 * time.Second

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
		// 约束整个解析过程（builtin + 系统 DNS 回退），使不可达的 DNS
		// 服务器无法让每次查询都把启动拖住 5 秒。
		ctx, cancel := context.WithTimeout(context.Background(), serverIPV6ResolveTimeout)
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

	client := &Client{
		cfg:           cfg,
		router:        rt,
		masterKey:     masterKey,
		fileWarn:      rt.CustomFileError(),
		closeIdleDone: make(chan struct{}),
	}
	client.bound.Store(boundIface{})

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
		ConnLifetime:      time.Duration(cfg.Transport.ConnLifetimeSec) * time.Second,
		ConnMaxBytes:      cfg.Transport.ConnMaxBytes,
		Timeout:           cfg.TimeoutDuration(),
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

// dialWithConfig 在 TUN 模式激活时使用绑定接口的直连拨号器拨号
// （使 socket 绕过 TUN 设备），否则回退到普通的 net.Dialer。
// 看似接口绑定过期的失败（休眠/唤醒、网络切换）会触发一次性
// 拨号器刷新与重试。
func (c *Client) dialWithConfig(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.router.ShouldIPV6Disable() {
		switch network {
		case "tcp":
			network = "tcp4"
		case "udp":
			network = "udp4"
		}
	}

	if c.cfg.Local.EnableTun2socks && c.dialer.Load() != nil {
		// 强制特定 IP 版本，直连拨号器的 socket 绑定（IP_BOUND_IF）
		// 才能生效。该拨号器只处理 "tcp4"/"udp4"，不处理双栈的
		// "tcp"/"udp"。
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

		conn, err := boundDialContext(c, ctx, network, addr)
		if err == nil || !isInterfaceStaleError(err) {
			return conn, err
		}

		// 绑定的接口过期了（休眠/唤醒、网络切换）：启动时捕获的接口
		// 不再路由。重新检测默认接口、重建拨号器并重试一次。
		log.Warn("[CLIENT] direct dial failed, refreshing interface binding", "addr", addr, "err", err)
		if c.refreshDirectDialer() {
			return boundDialContext(c, ctx, network, addr)
		}
		return conn, err
	}

	nd := &net.Dialer{
		KeepAlive: c.cfg.TimeoutDuration(),
	}
	return nd.DialContext(ctx, network, addr)
}

// refreshDirectDialer 在绑定变更（名称或索引）时重新检测默认接口并重建
// 绑定接口的直连拨号器。报告拨号器是否被替换。检测失败时保留现有拨号器，
// 使瞬态网络状态不会进一步降低连通性。在接口绑定不受支持的平台上
// （android）是返回 false 的空操作。
func (c *Client) refreshDirectDialer() bool {
	if ifaceBindUnsupported() {
		// 无法绑定直连拨号器的平台保持未绑定拨号器：没有可刷新的内容。
		return false
	}
	iface, err := detectDialIface()
	if err != nil {
		log.Warn("[CLIENT] refresh direct dialer: detect interface failed", "err", err)
		return false
	}
	if c.isTunIface(iface) {
		// 纵深防御：探测绝不应解析到 easyss TUN 设备（0.0.0.1 在 TUN
		// 路由之外），但旧脚本或自定义 TUN 配置留下的陈旧路由可能把它
		// 重定向到那里。绑定到它会让每次拨号都回环进 TUN 设备，
		// 因此保留先前绑定的物理接口。
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

// dialerRefreshLoop 周期性重新检测默认接口，使直连拨号器的接口绑定在
// 休眠/唤醒与网络切换后仍然有效：机器在不同网络上唤醒后，启动时捕获的
// 接口可能过期，使每次直连拨号在重启前都失败。在 darwin 和 linux 上
// 探测（0.0.0.1）位于 TUN 路由之外，在 Windows 上路由表查找会跳过
// TUN 设备，因此检测总是解析到物理接口；refreshDirectDialer 另外拒绝
// easyss TUN 设备，作为对旧脚本（覆盖 0.0.0.0/1）或自定义 TUN 配置
// 留下的陈旧路由的防御。
// 仅在 TUN 模式激活时运行（否则绑定的拨号器不被使用）。
func (c *Client) dialerRefreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if c.cfg.Local.EnableTun2socks {
				c.refreshDirectDialer()
			}
		case <-c.closeIdleDone:
			return
		}
	}
}

// isInterfaceStaleError 报告 err 是否像绑定的接口过期了（接口被移除、
// 宕机或不可达），以便重建拨号器并重试拨号。
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
	if ip := net.ParseIP(svr.Address); ip != nil {
		if ip.To4() == nil {
			return svr.Address
		}
		return ""
	}

	if dns.BuiltinDNSAvailable() {
		reachable := false
		for _, dnsServer := range config.DirectDNSServers {
			ips, err := dns.LookupIPV6FromContext(ctx, dnsServer, svr.Address)
			if err != nil {
				if ctx.Err() != nil {
					log.Warn("[CLIENT] server ipv6 resolution timed out", "server", svr.Address, "err", ctx.Err())
					return ""
				}
				continue
			}
			// 服务器应答了（可能为 NODATA），因此 builtin DNS
			// 服务器可达
			reachable = true
			if len(ips) == 0 {
				continue
			}
			dns.MarkBuiltinDNSAvailable()
			return ips[0].String()
		}
		if !reachable {
			// 只有存在系统 DNS 兜底时才熔断内置服务器：无兜底时熔断会让后续
			// 解析在冷却期内直接跳过仍可能可用的内置服务器（Android 上系统
			// DNS 对应用不可见，正是这种情形）。
			if len(dns.SystemDNSServers()) > 0 {
				dns.MarkBuiltinDNSUnavailable()
			}
			log.Warn("[CLIENT] all builtin direct dns servers failed to resolve server ipv6, fallback to system dns", "server", svr.Address)
		}
	}

	// 所有 builtin 直连 DNS 服务器都不可用时，回退到系统 DNS 服务器
	for _, dnsServer := range dns.SystemDNSServers() {
		ips, err := dns.LookupIPV6FromContext(ctx, dnsServer, svr.Address)
		if err != nil || len(ips) == 0 {
			if ctx.Err() != nil {
				log.Warn("[CLIENT] server ipv6 resolution timed out", "server", svr.Address, "err", ctx.Err())
				return ""
			}
			continue
		}
		return ips[0].String()
	}
	log.Warn("[CLIENT] failed to resolve server ipv6 via all direct and system dns servers", "server", svr.Address)
	return ""
}

func detectIPV6Networking() bool {
	_, _, err := util.SysGatewayAndDeviceV6()
	return err == nil
}

// RefreshServerIPV6 在服务端 IPv6 信息仍为空时重新解析一次，并更新路由引擎。
//
// 启动时若网络尚未就绪（开机自启动的典型情况），client.New 里的解析会得到
// 空值；降级启动后用户手动启用 TUN 时如果仍为空，平台脚本不会安装 IPv6 默认
// 路由，IPv6 流量就会绕过隧道（见 scripts/create_tun_dev*.sh）。已有值、服务器
// 是字面 IP、或 IPv6 规则为 disable 时直接返回，不做 DNS 查询。
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
	if svr := c.cfg.DefaultServer(); svr == nil || net.ParseIP(svr.Address) != nil {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), serverIPV6ResolveTimeout)
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

// StartupWarning 返回客户端初始化期间检测到的首个非致命警告
// （例如加载失败的自定义直连/代理规则文件），初始化干净完成时返回 nil。
// 客户端继续使用内置规则运行；调用方可以把警告呈现给用户。
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

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 按契约 Close 不具备幂等性（transport 无法重新打开），
	// 但第二次调用不得因重复关闭 channel 而 panic。
	c.closeOnce.Do(func() { close(c.closeIdleDone) })
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

func (c *Client) SetProxyRule(rule string) {
	pr := router.ParseProxyRule(rule)
	c.cfg.Routing.ProxyRule = rule
	c.router.SetProxyRule(pr)
}
