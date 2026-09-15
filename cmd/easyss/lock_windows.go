//go:build !headless && windows

package main

import (
	"errors"
	"os"

	"github.com/nange/easyss/v3/log"
	"golang.org/x/sys/windows"
)

var winLockHandle windows.Handle

// tryAcquireSingletonLock creates the named mutex that ensures only one
// instance of the app runs at a time. It returns errAnotherInstance when the
// mutex already exists, or the underlying error otherwise.
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

// acquireSingletonLock acquires the singleton lock, exiting the process when
// the lock is unavailable.
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

// releaseSingletonLock releases the named mutex.
func releaseSingletonLock() {
	if winLockHandle != 0 {
		_ = windows.CloseHandle(winLockHandle)
		winLockHandle = 0
	}
}
