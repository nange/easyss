//go:build !headless && windows

package app

import (
	"os"
	"time"
	"unsafe"

	"github.com/nange/easyss/v3/cmd/easyss/internal/singleton"
	"github.com/nange/easyss/v3/log"
	"golang.org/x/sys/windows"
)

// 新实例等旧实例撤完系统代理、拆完 TUN 的上限；超时宁可退出，也不要两个实例抢本地端口。
const handoffTimeout = 20 * time.Second

// MessageBoxW 的按钮/图标/前台标志，取值见 winuser.h。
const (
	mbOK            = 0x00000000
	mbIconError     = 0x00000010
	mbSetForeground = 0x00010000
)

var procMessageBoxW = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW")

// acquireInstance 取单实例锁。elevatedRestart 为 true 时本进程是"以管理员权限重启"的新
// 实例：旧实例正按正常退出流程收尾，这里要等它释放锁，否则 Acquire 会直接结束自己。
func acquireInstance(elevatedRestart bool) {
	if !elevatedRestart {
		singleton.Acquire()
		return
	}
	if err := singleton.AcquireAfterRestart(handoffTimeout); err != nil {
		log.Error("[EASYSS-V3] take over the previous instance", "err", err)
		showFatalMessage("Easyss 无法接管正在运行的实例（旧实例没有在时限内退出），" +
			"系统全局流量未开启。\n\n详情：" + err.Error())
		os.Exit(1)
	}
}

// showFatalMessage 用于托盘还没建起来的启动失败：windowsgui 构建没有控制台，
// 只写日志等于静默退出，用户只会看到"点了 UAC 之后什么都没发生"。
func showFatalMessage(msg string) {
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return
	}
	caption, _ := windows.UTF16PtrFromString("Easyss")
	_, _, _ = procMessageBoxW.Call(0,
		uintptr(unsafe.Pointer(text)),
		uintptr(unsafe.Pointer(caption)),
		mbOK|mbIconError|mbSetForeground)
}
