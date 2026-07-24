//go:build !without_tray

package main

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"fyne.io/systray"
	"github.com/nange/easyss/v3/log"
)

func runApp(disableTray, daemon bool, app *App) {
	acquireSingletonLock()
	defer releaseSingletonLock()

	if !disableTray && (runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "linux") {
		// On macOS and Linux, daemonize before starting the tray app so that
		// closing the terminal does not terminate the process.
		if daemon && runtime.GOOS != "windows" {
			runDaemon()
		}

		ta := &TrayApp{
			App:     app,
			closing: make(chan struct{}),
		}

		go func() {
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

			select {
			case sig := <-c:
				log.Info("[EASYSS-V3] got signal to exit", "signal", sig)
				systray.Quit()
			case <-ta.closing:
				log.Info("[EASYSS-V3] easyss exiting...")
			}
		}()

		systray.Run(ta.trayReady, ta.trayExit)
	} else if daemon && runtime.GOOS != "windows" {
		runDaemon()
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
		sigWait()

		if proxyWasSet {
			_ = unsetSysProxy()
		}
		app.Stop()
		os.Exit(0)
	}
}
