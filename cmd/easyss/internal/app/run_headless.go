//go:build headless

package app

import (
	"os"
	"runtime"

	"github.com/nange/easyss/v3/log"
)

func (a *App) Run(disableTray, daemon, elevatedRestart bool) {
	_ = disableTray
	// headless 没有托盘，也就没有"以管理员权限重启"的入口。
	_ = elevatedRestart

	if daemon && runtime.GOOS != "windows" {
		runDaemon()
	}

	if err := a.Start(); err != nil {
		log.Error("[EASYSS-V3] start", "err", err)
		a.Stop()
		os.Exit(1)
	}
	// 必须在核心启动成功、本地端口已监听之后设置，否则系统会指向一个尚未监听的端口。
	// 降级启动也要设置：headless 没有托盘菜单，跳过就等于用户再无入口打开它。
	a.setupSysProxy()
	if warn := a.currentStartupWarn(); warn != nil {
		log.Warn("[EASYSS-V3] startup warning", "err", warn)
	}
	sigWait()
	// App.Stop 统一按“撤销系统代理 → 拆 TUN → 停核心”的顺序收尾；os.Exit
	// 不会执行 defer，因此必须显式调用。
	a.Stop()
	os.Exit(0)
}
