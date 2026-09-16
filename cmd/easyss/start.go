//go:build !headless

package main

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/nange/easyss/v3/log"
)

func runApp(disableTray, daemon bool, app *App) {
	// 在 macOS 和 Linux 上，先守护化（daemonize）再获取单例锁，
	// 这样关闭终端不会终止进程。锁必须由子进程获取，而不是父进程。
	if daemon && runtime.GOOS != "windows" {
		runDaemon()
	}

	acquireSingletonLock()
	defer releaseSingletonLock()

	if !disableTray && (runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux") {
		ta := &TrayApp{
			App:       app,
			closing:   make(chan struct{}),
			trayBuilt: make(chan struct{}),
		}

		go func() {
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

			select {
			case sig := <-c:
				log.Info("[EASYSS-V3] got signal to exit", "signal", sig)
				// 等待 buildTray() 完成，这样托盘非 nil，
				// Remove() 才能终止消息循环。
				<-ta.trayBuilt
				ta.tray.Remove()
			case <-ta.closing:
				log.Info("[EASYSS-V3] easyss exiting...")
			}
		}()

		ta.buildTray()
		close(ta.trayBuilt)
		_ = ta.tray.Run()
		ta.trayExit()
	} else {
		proxyWasSet := false
		if !app.cfg.Local.DisableSysProxy && app.cfg.Local.HTTPPort > 0 {
			if err := setSysProxy(app.cfg.Local.HTTPPort); err != nil {
				log.Warn("[EASYSS-V3] set system proxy failed, you may need to configure it manually", "err", err)
			} else {
				proxyWasSet = true
			}
		}

		if err := app.Start(); err != nil {
			log.Error("[EASYSS-V3] start", "err", err)
			if proxyWasSet {
				_ = unsetSysProxy()
			}
			os.Exit(1)
		}
		if app.startupWarn != nil {
			log.Warn("[EASYSS-V3] startup warning (no tray to notify)", "err", app.startupWarn)
		}
		sigWait()

		if proxyWasSet {
			_ = unsetSysProxy()
		}
		app.Stop()
		os.Exit(0)
	}
}
