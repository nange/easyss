//go:build !headless && windows

package app

import (
	"os"
	"time"

	"github.com/nange/easyss/v3/cmd/easyss/internal/singleton"
	"github.com/nange/easyss/v3/log"
)

// 新实例等旧实例撤完系统代理、拆完 TUN 的上限；超时宁可退出，也不要两个实例抢本地端口。
const handoffTimeout = 20 * time.Second

// acquireInstance 取单实例锁。elevatedRestart 为 true 时本进程是"以管理员权限重启"的新实例：
// 必须先请旧实例退出再抢锁，否则 Acquire 会因为它还没退完而直接结束自己。
func acquireInstance(elevatedRestart bool) {
	if !elevatedRestart {
		singleton.Acquire()
		return
	}
	if err := singleton.AcquireAfterRestart(handoffTimeout); err != nil {
		log.Error("[EASYSS-V3] take over the running instance", "err", err)
		os.Exit(1)
	}
}

// watchRestartRequest 等新实例请求接管，然后走与托盘"退出"相同的收尾：Run 返回后主
// goroutine 撤系统代理 → 拆 TUN → 停核心，进程退出即释放互斥量。
func (a *trayApp) watchRestartRequest() {
	go func() {
		if !singleton.WaitRestartRequest() {
			return
		}
		log.Info("[SYSTRAY] handing the instance over to an elevated copy")
		a.notify("正在以管理员权限重启…")
		a.shell.Remove()
	}()
}
