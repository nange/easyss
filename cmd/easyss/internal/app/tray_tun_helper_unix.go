//go:build (darwin || linux) && !headless

package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/cmd/easyss/internal/tunhelper"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

// tunUpAuto 返回本平台的启用路径：非 root 时拉起提权 helper，root 直接创建设备。
func (s *session) tunUpAuto() error {
	if !tunhelper.IsRoot() {
		return s.tunUpViaHelper()
	}
	return s.tunUp()
}

// 生成长期运行的提权 helper 打开设备、配置路由/DNS 并传回 fd；helper 靠 stdin（FIFO）感知主进程生命周期。
func (s *session) tunUpViaHelper() error {
	// 与 session.tunUp、session.tunDown 共用 tunMu。
	s.tunMu.Lock()
	defer s.tunMu.Unlock()

	// 核心与配置在入口取一次快照：这条路径要提权、spawn、等 fd（最长数十秒），期间 Stop/切换可能已换掉状态。
	core := s.currentCore()
	cfg := s.app.currentConfig()

	log.Info("[SYSTRAY] tunUpViaHelper called",
		"tunMgrNil", s.tunMgr == nil,
		"coreNil", core == nil)

	if s.tunMgr != nil {
		log.Warn("[SYSTRAY] tunMgr already set, skipping create")
		return nil
	}

	if core == nil || core.Client == nil {
		return fmt.Errorf("client not initialized")
	}

	// 用临时 manager 构建 TunConfig 以取设备默认值；配置来自共享 builder，与直连路径同源。
	tmpCfg := s.tunConfig()
	tmpMgr := tun.New(tmpCfg)
	devCfg := tmpMgr.DeviceConfig()

	if core.HTTPServer == nil {
		return fmt.Errorf("http proxy server not started")
	}

	// 预解析失败也要清掉上一次留下的 TUN 配置：HTTP 入口不能继续指向一个没起来的设备。
	ok := false
	defer func() {
		if !ok {
			core.HTTPServer.ClearTunConfig()
		}
	}()

	// 必须先生成 helper 之前预解析服务器主机名并填缓存，否则 helper 把系统 DNS 指向 TUN 后会形成循环依赖。
	// 只做一次有界尝试（dns.PreResolveTimeout）：用户主动触发，失败就报错让其重试，不在界面无反馈时叠成"次数 × 预算"。
	if err := preResolveHelperServer(core, cfg); err != nil {
		return err
	}

	core.HTTPServer.SetTunConfig(newHelperTunConfig(cfg, devCfg))

	fd, fifo, err := spawnHelperTun(cfg)
	if err != nil {
		return err
	}

	s.installHelperTun(core, cfg, fd, devCfg)
	s.tunHelperStdin = fifo
	ok = true
	return nil
}

// preResolveHelperServer 在 helper 接管系统 DNS 之前填充服务端域名缓存，避免解析递归。
func preResolveHelperServer(core *runner.Core, cfg *clientconfig.ClientConfig) error {
	serverAddr := cfg.DefaultServer().Host
	if util.IsIP(serverAddr) {
		return nil
	}
	if len(clientconfig.DirectDNSServers) == 0 {
		return fmt.Errorf("failed to pre-resolve server hostname %s: dns cache not available", serverAddr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dns.PreResolveTimeout)
	// 缓存由核心持有（runner.Core.PrePopulateServerDomain），是 DNS pinning 与 TUN 系统 DNS 的同一来源。
	err := core.PrePopulateServerDomain(ctx, serverAddr, clientconfig.DirectDNSServers,
		cfg.Routing.IPV6Rule != "enable")
	cancel()
	if err != nil {
		return fmt.Errorf("failed to pre-resolve server hostname %s: %w", serverAddr, err)
	}
	log.Info("[SYSTRAY] pre-populated dns cache for server", "host", serverAddr)
	return nil
}

// newHelperTunConfig 由与直连路径相同的设备快照构造 helper 配置。必须在预解析之后调用：
// 只有成功过的解析器才可能被记录（见 dns.PreferredSystemDNS），先取值会把已知不可达的默认值写进系统 DNS。
// MTU 与稍后交给 netstack 的值同源：helper 写进设备、主进程设 netstack，不一致时 netstack 会静默丢弃超限包。
func newHelperTunConfig(cfg *clientconfig.ClientConfig, dev tun.DeviceConfig) *proxy.TunConfig {
	return &proxy.TunConfig{
		Socks5Addr:     util.Socks5URI(cfg.Local.BindAll, cfg.Local.SocksPort),
		DNSAddr:        tunDNS(),
		Device:         dev.Device,
		TunIP:          dev.TunIP,
		TunGW:          dev.TunGW,
		TunMask:        dev.TunMask,
		TunIPV6Sub:     dev.TunIPV6Sub,
		TunGWV6:        dev.TunGWV6,
		ServerIPV6:     dev.ServerIPV6,
		LocalGateway:   dev.LocalGateway,
		LocalGatewayV6: dev.LocalGatewayV6,
		MTU:            cfg.TunMTU(),
	}
}

// spawnHelperTun 拉起提权 helper 并接收 TUN fd；失败时释放本次已建立的全部资源。
// 生成等待上限取归一化后的基础超时；helper 经 httpAddr 取配置，地址必须与本地 HTTP 入口监听同源
// （util.LocalProxyDialAddr），写死 127.0.0.1 会在 bind_all 且只接受 IPv6 回环时让 TUN 无法启用。
func spawnHelperTun(cfg *clientconfig.ClientConfig) (int, io.WriteCloser, error) {
	spawnTimeout := cfg.TimeoutDuration()
	fdSocketPath := tunhelper.FdSocketPath()
	httpAddr := util.LocalProxyDialAddr(cfg.Local.BindAll, cfg.Local.HTTPPort)
	fifoWriter, fdListener, err := tunhelper.Spawn(httpAddr, fdSocketPath,
		cfg.Log.FilePath, cfg.Log.Level, spawnTimeout)
	if err != nil {
		return -1, nil, fmt.Errorf("spawn tun helper: %w", err)
	}

	fd, err := tunhelper.ReceiveFd(fdListener)
	fdListener.Close() //nolint:errcheck
	if runtime.GOOS != "linux" {
		os.Remove(fdSocketPath) //nolint:errcheck
	}
	if err != nil {
		fifoWriter.Close() //nolint:errcheck
		return -1, nil, fmt.Errorf("receive tun fd: %w", err)
	}

	// 必须非阻塞，Go 的 netpoller 才能在 engine.Stop() 关闭 fd 时唤醒 dispatchLoop；O_NONBLOCK 可能在 macOS 的 SCM_RIGHTS 传输中丢失。
	if err := unix.SetNonblock(fd, true); err != nil {
		// 裸 fd 尚未交给任何持有者：不在这里关闭会永久泄漏，并让 Linux 上的 TUN 设备无法随最后一个 fd 消失。
		_ = unix.Close(fd)
		fifoWriter.Close() //nolint:errcheck
		return -1, nil, fmt.Errorf("set nonblock: %w", err)
	}
	return fd, fifoWriter, nil
}

func (s *session) installHelperTun(core *runner.Core, cfg *clientconfig.ClientConfig, fd int, dev tun.DeviceConfig) {
	// 偏好进不可变快照，运行期状态由 adoptTunManager 在同一临界区里发布。
	s.app.updateConfig(func(c *clientconfig.ClientConfig) { c.Local.EnableTun2socks = true })

	mgr := tun.New(tun.Config{
		Socks5Addr: util.Socks5URI(cfg.Local.BindAll, cfg.Local.SocksPort),
		// DeviceFD>0 即 fd 路径，owner 由它推导为 OwnerHelper：路由与系统 DNS 归 helper 回收，主进程只停引擎并关 fd。
		DeviceFD: fd,
		// netstack 这一侧要与 helper 创建设备时的值一致；不一致时 Manager.engineMTU 按设备真实值兜底并告警。
		MTU: cfg.TunMTU(),
	})
	// 记下 helper 建立会话时用的设备/网关配置：关闭时要按它核对路由与回滚，而 manager 只知道请求的设备名
	// （fd 路径下内核分配的 utunN 只有 helper 见过）。
	s.adoptTunManager(mgr, &dev, tun.OwnerHelper)
	s.buildICMPHandler(core)
	s.startTunEngine(mgr, "fd")
}
