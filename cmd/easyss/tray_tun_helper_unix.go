//go:build (darwin || linux) && !headless

package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

// createTun2socksViaHelper 生成一个长期运行的提权 helper 来打开
// TUN 设备、配置路由/DNS，并将 fd 传回。helper 持续存活，
// 监控其 stdin（一个 FIFO）以接收主进程的生命周期信号。
func (a *TrayApp) createTun2socksViaHelper() error {
	a.tunHelperMu.Lock()
	defer a.tunHelperMu.Unlock()

	log.Info("[SYSTRAY] createTun2socksViaHelper called",
		"tunMgrNil", a.tunMgr == nil,
		"coreNil", a.core == nil)

	if a.tunMgr != nil {
		log.Warn("[SYSTRAY] tunMgr already set, skipping create")
		return nil
	}

	if a.core == nil || a.core.Client == nil {
		return fmt.Errorf("client not initialized")
	}

	// 1. 用临时 manager 构建 TunConfig 以获取设备默认值。
	// manager 配置来自共享 builder，因此此路径与直接路径使用相同的
	// socks/dns/server-ipv6 值（它同时会刷新服务端 IPv6）。
	tmpCfg := a.tunConfig()
	tmpMgr := tun.New(tmpCfg)
	devCfg := tmpMgr.DeviceConfig()

	if a.core.HTTPServer == nil {
		return fmt.Errorf("http proxy server not started")
	}

	// 2. 在生成 helper 之前预解析代理服务器主机名并填充 DNS 缓存，
	// 以避免 helper 将系统 DNS 指向 TUN 后产生循环依赖。
	//
	// 只做一次有界尝试（预算为 dns.PreResolveTimeout，与启动期预解析同一个
	// 常量）：这是用户主动触发的操作，失败就报错让用户重试，而不是在界面无
	// 反馈的情况下把最坏等待叠成"尝试次数 × 总预算"。
	if serverAddr := a.cfg.DefaultServer().Address; !util.IsIP(serverAddr) {
		if len(config.DirectDNSServers) == 0 {
			a.core.HTTPServer.ClearTunConfig()
			return fmt.Errorf("failed to pre-resolve server hostname %s: dns cache not available", serverAddr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), dns.PreResolveTimeout)
		// 缓存由核心持有（见 runner.Core.PrePopulateServerDomain）：它是 DNS
		// pinning 与 TUN 系统 DNS 的同一个来源，不再经由本地 SOCKS5 服务器。
		err := a.core.PrePopulateServerDomain(ctx, serverAddr, config.DirectDNSServers,
			a.cfg.Routing.IPV6Rule != "enable")
		cancel()
		if err != nil {
			a.core.HTTPServer.ClearTunConfig()
			return fmt.Errorf("failed to pre-resolve server hostname %s: %w", serverAddr, err)
		}
		log.Info("[SYSTRAY] pre-populated dns cache for server", "host", serverAddr)
	}

	// 3. 预解析之后再取 tunDNS 并注册配置：预解析成功的内置/系统解析器只有在这
	// 之后才可能被记录（见 dns.PreferredSystemDNS）。先取值会让"此前所有标记
	// 尝试都失败、恰好这次预解析才成功"的情形把 TUN 的系统 DNS 写成已知不可达的
	// 默认值。
	//
	// MTU 取 tmpCfg.MTU（由 a.cfg.TunMTU() 归一化而来），与稍后交给 tun2socks
	// netstack 的值同源：helper 把它交给创建脚本写进设备，主进程用它设置
	// netstack，二者不一致时 netstack 会静默丢弃超过自身 MTU 的包
	// （见 tun.Manager.engineMTU）。
	tunHTTPCfg := &proxy.TunConfig{
		Socks5Addr:     util.Socks5URI(a.cfg.Local.SocksPort),
		DNSAddr:        tunDNS(),
		Device:         devCfg.Device,
		TunIP:          devCfg.TunIP,
		TunGW:          devCfg.TunGW,
		TunMask:        devCfg.TunMask,
		TunIPV6Sub:     devCfg.TunIPV6Sub,
		TunGWV6:        devCfg.TunGWV6,
		ServerIPV6:     devCfg.ServerIPV6,
		LocalGateway:   devCfg.LocalGateway,
		LocalGatewayV6: devCfg.LocalGatewayV6,
		MTU:            tmpCfg.MTU,
	}

	// 让 helper 可以通过 GET /tun 获取配置。
	a.core.HTTPServer.SetTunConfig(tunHTTPCfg)

	// 4. 生成提权 helper。将归一化后的基础超时作为生成等待上限
	//    （未配置时为默认值 30s，越界值已在加载时钳制）。
	spawnTimeout := a.cfg.TimeoutDuration()
	fdSocketPath := tunFdSocketPath()
	fifoWriter, fdListener, err := SpawnTunHelper(a.cfg.Local.HTTPPort, fdSocketPath,
		a.cfg.Log.FilePath, a.cfg.Log.Level, spawnTimeout)
	if err != nil {
		a.core.HTTPServer.ClearTunConfig()
		return fmt.Errorf("spawn tun helper: %w", err)
	}

	// 5. 从 helper 接收 TUN fd。
	fd, err := ReceiveFd(fdListener)
	fdListener.Close() //nolint:errcheck
	if runtime.GOOS != "linux" {
		os.Remove(fdSocketPath) //nolint:errcheck
	}
	if err != nil {
		fifoWriter.Close() //nolint:errcheck
		a.core.HTTPServer.ClearTunConfig()
		return fmt.Errorf("receive tun fd: %w", err)
	}

	// 确保 fd 是非阻塞的，这样 Go 的 netpoller (kqueue) 能在 engine.Stop()
	// 关闭 fd 时可靠地唤醒 iobased dispatchLoop。
	// O_NONBLOCK 标志可能在 macOS 的 SCM_RIGHTS 传输过程中丢失。
	if err := unix.SetNonblock(fd, true); err != nil {
		// 这个裸 fd 尚未交给任何持有者：不在这里关闭就会永久泄漏，并让
		// Linux 上的 TUN 设备无法随最后一个 fd 消失。
		_ = unix.Close(fd)
		fifoWriter.Close() //nolint:errcheck
		a.core.HTTPServer.ClearTunConfig()
		return fmt.Errorf("set nonblock: %w", err)
	}

	// 6. 使用接收到的 fd 创建 tun manager。
	a.cfg.Local.EnableTun2socks = true
	a.tunMgr = tun.New(tun.Config{
		Socks5Addr:       util.Socks5URI(a.cfg.Local.SocksPort),
		DeviceFD:         fd,
		SkipRouteCleanup: true, // helper 负责路由/DNS 清理
		// 设备由 helper 按同一个值创建（见 tunHTTPCfg.MTU）；这里是 netstack
		// 那一侧。若两者不一致，Manager.engineMTU 会按设备真实值兜底并告警。
		MTU: a.cfg.TunMTU(),
	})

	icmpHandler := tun.NewICMPHandler(a.core.Client.Router())
	icmpHandler.SetProxy(a.core.StreamHandler, a.methodFromServer())
	a.tunMgr.SetICMPHandler(icmpHandler)

	startTunEngine(a.tunMgr, "fd")

	a.tunHelperStdin = fifoWriter

	return nil
}
