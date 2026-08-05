//go:build (darwin || linux) && !headless

package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"golang.org/x/sys/unix"
)

// createTun2socksViaHelper spawns a long-running elevated helper to open the
// TUN device, set up routes/DNS, and pass the fd back. The helper stays alive
// monitoring its stdin (a FIFO) for the main process lifecycle signal.
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

	// 1. Build TunConfig from the temporary manager to get device defaults.
	tmpCfg := tun.Config{
		Socks5Addr: fmt.Sprintf("socks5://127.0.0.1:%d", a.cfg.Local.SocksPort),
		DNSServer:  tunDNS(a.cfg),
	}
	if ipv6 := a.core.Client.Router().ServerIPV6(); ipv6 != "" {
		tmpCfg.ServerIPV6 = ipv6
	}
	tmpMgr := tun.New(tmpCfg)
	devCfg := tmpMgr.DeviceConfig()

	tunHTTPCfg := &proxy.TunConfig{
		Socks5Addr:     fmt.Sprintf("socks5://127.0.0.1:%d", a.cfg.Local.SocksPort),
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

	// 2. Register the config so the helper can fetch it via GET /tun.
	if a.core.HTTPServer == nil {
		return fmt.Errorf("http proxy server not started")
	}
	a.core.HTTPServer.SetTunConfig(tunHTTPCfg)

	// 3. Pre-resolve the proxy server hostname and populate the DNS cache
	// before spawning the helper, to avoid a circular dependency once the
	// helper sets the system DNS to go through TUN.
	if serverAddr := a.cfg.DefaultServer().Address; net.ParseIP(serverAddr) == nil {
		var err error
		for i := 0; i < 3; i++ {
			if a.core.SocksServer == nil || len(config.DirectDNSServers) == 0 {
				err = fmt.Errorf("dns cache not available")
				break
			}
			err = a.core.SocksServer.PrePopulateDNS(serverAddr, config.DirectDNSServers[0],
				a.cfg.Routing.IPV6Rule != "enable")
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

	// 4. Spawn the elevated helper. Use the configured timeout (seconds) as
	//    the spawn wait limit; fall back to 30s if unset or invalid.
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

	// 5. Receive the TUN fd from the helper.
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

	// Ensure the fd is non-blocking so Go's netpoller (kqueue) reliably
	// wakes up the iobased dispatchLoop when engine.Stop() closes the fd.
	// The O_NONBLOCK flag may be lost during SCM_RIGHTS transfer on macOS.
	if err := unix.SetNonblock(fd, true); err != nil {
		fifoWriter.Close() //nolint:errcheck
		a.core.HTTPServer.ClearTunConfig()
		return fmt.Errorf("set nonblock: %w", err)
	}

	// 6. Create the tun manager using the received fd.
	a.cfg.Local.EnableTun2socks = true
	a.tunMgr = tun.New(tun.Config{
		Socks5Addr:       fmt.Sprintf("socks5://127.0.0.1:%d", a.cfg.Local.SocksPort),
		DeviceFD:         fd,
		SkipRouteCleanup: true, // helper handles route/DNS cleanup
	})

	icmpHandler := tun.NewICMPHandler(a.core.Client.Router())
	icmpHandler.SetProxy(a.core.StreamHandler, methodFromString(a.cfg.DefaultServer().Method))
	a.tunMgr.SetICMPHandler(icmpHandler)

	go func() {
		if err := a.tunMgr.Start(); err != nil {
			log.Error("[SYSTRAY] tun2socks start (fd)", "err", err)
		}
	}()

	a.tunHelperStdin = fifoWriter

	return nil
}
