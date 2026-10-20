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
		app.Stop()
		os.Exit(1)
	}
	// 必须在核心启动成功、本地端口已监听之后设置，否则系统会指向一个尚未监听的端口。
	// 降级启动也要设置：headless 没有托盘菜单，跳过就等于用户再无入口打开它。
	app.setupSysProxy()
	if warn := app.currentStartupWarn(); warn != nil {
		log.Warn("[EASYSS-V3] startup warning", "err", warn)
	}
	sigWait()
	// App.Stop 统一按“撤销系统代理 → 拆 TUN → 停核心”的顺序收尾；os.Exit
	// 不会执行 defer，因此必须显式调用。
	app.Stop()
	os.Exit(0)
}
