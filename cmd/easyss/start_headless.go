//go:build headless

package main

import (
	"os"
	"runtime"

	"github.com/nange/easyss/v3/log"
)

func runApp(disableTray, daemon bool, app *App) {
	_ = disableTray

	if daemon && runtime.GOOS != "windows" {
		runDaemon()
	}

	if err := app.Start(); err != nil {
		log.Error("[EASYSS-V3] start", "err", err)
		os.Exit(1)
	}
	if app.startupWarn != nil {
		log.Warn("[EASYSS-V3] startup warning", "err", app.startupWarn)
	}
	sigWait()
	app.Stop()
	os.Exit(0)
}
