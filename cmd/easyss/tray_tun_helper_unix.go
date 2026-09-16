//go:build (darwin || linux) && !headless

package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

// tunHelperResolveTimeout 限制生成 TUN helper 之前对每个服务端域名进行
// 预解析的耗时（这是一个运行时开关，不同于 runner.Run 内部的启动检查）。
// 与 runner.serverStartupResolveTimeout 保持同步。
const tunHelperResolveTimeout = 3 * time.Second

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
	// socks/dns/server-ipv6 值。
	tmpCfg := a.tunConfig()
	tmpMgr := tun.New(tmpCfg)
	devCfg := tmpMgr.DeviceConfig()

	tunHTTPCfg := &proxy.TunConfig{
		Socks5Addr:     util.Socks5URI(a.cfg.Local.SocksPort),
		DNSAddr:        tunDNS(a.cfg),
		Device:         devCfg.Device,
		TunIP:          devCfg.TunIP,
		TunGW:          devCfg.TunGW,
		TunMask:        devCfg.TunMask,
		TunIPV6Sub:     devCfg.TunIPV6Sub,
		TunGWV6:        devCfg.TunGWV6,
		ServerIPV6:     devCfg.ServerIPV6,
		LocalGateway:   devCfg.LocalGateway,
		LocalGatewayV6: devCfg.LocalGatewayV6,
		MTU:            1500,
	}

	// 2. 注册配置，让 helper 可以通过 GET /tun 获取它。
	if a.core.HTTPServer == nil {
		return fmt.Errorf("http proxy server not started")
	}
	a.core.HTTPServer.SetTunConfig(tunHTTPCfg)

	// 3. 在生成 helper 之前预解析代理服务器主机名并填充 DNS 缓存，
	// 以避免 helper 将系统 DNS 指向 TUN 后产生循环依赖。
	if serverAddr := a.cfg.DefaultServer().Address; !util.IsIP(serverAddr) {
		var err error
		for i := range 3 {
			if a.core.SocksServer == nil || len(config.DirectDNSServers) == 0 {
				err = fmt.Errorf("dns cache not available")
				break
			}
			ctx, cancel := context.WithTimeout(context.Background(), tunHelperResolveTimeout)
			err = a.core.SocksServer.PrePopulateDNS(ctx, serverAddr, config.DirectDNSServers,
				a.cfg.Routing.IPV6Rule != "enable")
			cancel()
			if err == nil {
				log.Info("[SYSTRAY] pre-populated dns cache for server", "host", serverAddr)
				break
			}
			if i < 2 {
				time.Sleep(time.Second)
			}
		}
		if err != nil {
			a.core.HTTPServer.ClearTunConfig()
			return fmt.Errorf("failed to pre-resolve server hostname %s: %w", serverAddr, err)
		}
	}

	// 4. 生成提权 helper。将配置的超时时间（秒）作为生成等待上限；
	//    未设置或无效时回退到 30s。
	spawnTimeout := 30 * time.Second
	if a.cfg.Timeout > 0 {
		spawnTimeout = time.Duration(a.cfg.Timeout) * time.Second
	}
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
	})

	icmpHandler := tun.NewICMPHandler(a.core.Client.Router())
	icmpHandler.SetProxy(a.core.StreamHandler, a.methodFromServer())
	a.tunMgr.SetICMPHandler(icmpHandler)

	startTunEngine(a.tunMgr, "fd")

	a.tunHelperStdin = fifoWriter

	return nil
}
