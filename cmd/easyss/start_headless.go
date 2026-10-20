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
	// 系统代理在核心启动成功之后才设置：此时本地 HTTP 端口已经监听，
	// 不存在"系统被指向一个尚未监听的端口"的窗口，Start 失败也无需回滚。
	// 降级启动（服务端域名尚未解析出来）同样设置：headless 没有托盘菜单，
	// 跳过就意味着用户再无入口打开它，而 headless 客户端本地代理会按
	// 代理规则分流，直连规则的流量在隧道恢复前也仍然可用。
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
