//go:build !headless && windows

package main

import (
	"errors"
	"os"

	"github.com/nange/easyss/v3/log"
	"golang.org/x/sys/windows"
)

var winLockHandle windows.Handle

// tryAcquireSingletonLock 创建确保同一时刻只运行一个应用实例的命名互斥量。
// 互斥量已存在时返回 errAnotherInstance，否则返回底层错误。
func tryAcquireSingletonLock() error {
	name, _ := windows.UTF16PtrFromString("Global\\Easyss_Singleton")
	handle, err := windows.CreateMutex(nil, false, name)
	switch {
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
		return errAnotherInstance
	case err != nil:
		return err
	}
	winLockHandle = handle
	return nil
}

// acquireSingletonLock 获取单实例锁，锁不可用时退出进程。
func acquireSingletonLock() {
	err := tryAcquireSingletonLock()
	switch {
	case err == nil:
		return
	case errors.Is(err, errAnotherInstance):
		log.Warn("[EASYSS-V3] another instance is already running, exiting")
		os.Exit(0)
	default:
		log.Error("[EASYSS-V3] failed to create mutex", "err", err)
		os.Exit(1)
	}
}

// releaseSingletonLock 释放命名互斥量。
func releaseSingletonLock() {
	if winLockHandle != 0 {
		_ = windows.CloseHandle(winLockHandle)
		winLockHandle = 0
	}
}
