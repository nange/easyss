//go:build !headless && windows

package singleton

import (
	"errors"
	"os"

	"github.com/nange/easyss/v3/log"
	"golang.org/x/sys/windows"
)

var winLockHandle windows.Handle

// TryAcquire 创建确保同一时刻只运行一个应用实例的命名互斥量。
// 互斥量已存在时返回 ErrAnotherInstance，否则返回底层错误。
func TryAcquire() error {
	name, _ := windows.UTF16PtrFromString("Global\\Easyss_Singleton")
	handle, err := windows.CreateMutex(nil, false, name)
	switch {
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		return ErrAnotherInstance
	case err != nil:
		return err
	}
	winLockHandle = handle
	return nil
}

// Acquire 获取单实例锁，锁不可用时退出进程。
func Acquire() {
	err := TryAcquire()
	switch {
	case err == nil:
		return
	case errors.Is(err, ErrAnotherInstance):
		log.Warn("[EASYSS-V3] another instance is already running, exiting")
		os.Exit(0)
	default:
		log.Error("[EASYSS-V3] failed to create mutex", "err", err)
		os.Exit(1)
	}
}

// Release 释放命名互斥量。
func Release() {
	if winLockHandle != 0 {
		_ = windows.CloseHandle(winLockHandle)
		winLockHandle = 0
	}
}
