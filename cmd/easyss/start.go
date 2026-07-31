//go:build !without_tray

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
		// Pin this goroutine to its OS thread: the tray window is created on
		// the current thread and the message loop must run on the same thread
		// (Win32 message queues are per-thread). Without this, the Go runtime
		// may migrate the goroutine after blocking syscalls in Start().
		runtime.LockOSThread()

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
				if ta.tray != nil {
					ta.tray.Remove()
				}
			case <-ta.closing:
				log.Info("[EASYSS-V3] easyss exiting...")
			}
		}()

		ta.buildTray()
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
