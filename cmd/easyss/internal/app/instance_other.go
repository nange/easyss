//go:build !headless && !windows

package app

import "github.com/nange/easyss/v3/cmd/easyss/internal/singleton"

// acquireInstance 与 Windows 共用这一处调用点；"以管理员权限重启"只有 Windows 有，
// darwin/linux 的提权由 tunUpAuto 用 pkexec/osascript 原地发起。
func acquireInstance(bool) { singleton.Acquire() }

// watchRestartRequest 在非 Windows 平台没有跨进程的提权交接。
func (*trayApp) watchRestartRequest() {}
