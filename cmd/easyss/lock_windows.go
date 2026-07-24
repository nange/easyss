//go:build !without_tray && windows

package main

import (
	"os"

	"github.com/nange/easyss/v3/log"
	"golang.org/x/sys/windows"
)

var winLockHandle windows.Handle

// acquireSingletonLock creates a named mutex to ensure only one instance
// of the app runs at a time.
func acquireSingletonLock() {
	name, _ := windows.UTF16PtrFromString("Global\\Easyss_Singleton")
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		log.Error("[EASYSS-V3] failed to create mutex", "err", err)
		os.Exit(1)
	}
	if windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		windows.CloseHandle(handle)
		log.Warn("[EASYSS-V3] another instance is already running, exiting")
		os.Exit(0)
	}
	winLockHandle = handle
}

// releaseSingletonLock releases the named mutex.
func releaseSingletonLock() {
	if winLockHandle != 0 {
		windows.CloseHandle(winLockHandle)
		winLockHandle = 0
	}
}
