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
	// On macOS and Linux, daemonize before acquiring the singleton lock so that
	// closing the terminal does not terminate the process. The lock must be
	// acquired by the child process, not the parent.
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
				// Wait for buildTray() to finish so the tray is non-nil and
				// Remove() can terminate the message loop.
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
		sigWait()

		if proxyWasSet {
			_ = unsetSysProxy()
		}
		app.Stop()
		os.Exit(0)
	}
}
