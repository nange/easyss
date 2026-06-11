//go:build !without_tray

package main

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/getlantern/systray"
	"github.com/nange/easyss/v3/log"
)

func runApp(disableTray, daemon bool, app *App) {
	if !disableTray && (runtime.GOOS == "windows" || runtime.GOOS == "darwin") {
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
		if err := app.Start(); err != nil {
			log.Error("[EASYSS-V3] start", "err", err)
			os.Exit(1)
		}
		sigWait()
		app.Stop()
		os.Exit(0)
	}
}
