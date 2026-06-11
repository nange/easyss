//go:build without_tray

package main

import (
	"os"

	"github.com/nange/easyss/v3/log"
)

func runApp(disableTray, daemon bool, app *App) {
	_ = disableTray
	_ = daemon

	if err := app.Start(); err != nil {
		log.Error("[EASYSS-V3] start", "err", err)
		os.Exit(1)
	}
	sigWait()
	app.Stop()
	os.Exit(0)
}
