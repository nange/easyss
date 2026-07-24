//go:build !without_tray && (darwin || linux)

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/nange/easyss/v3/log"
)

var singletonLockFile *os.File

// acquireSingletonLock acquires an exclusive file lock to ensure only one
// instance of the app runs at a time. If another instance is already running,
// it exits gracefully. Must be called after daemonization.
func acquireSingletonLock() {
	lockPath := filepath.Join(os.TempDir(), fmt.Sprintf("easyss-%d.lock", os.Getuid()))

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		log.Error("[EASYSS-V3] failed to open lock file", "err", err)
		os.Exit(1)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		log.Warn("[EASYSS-V3] another instance is already running, exiting")
		_ = f.Close()
		os.Exit(0)
	}

	// Write PID for diagnostic purposes.
	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())

	singletonLockFile = f
}

// releaseSingletonLock releases the file lock and cleans up the lock file.
func releaseSingletonLock() {
	if singletonLockFile != nil {
		_ = syscall.Flock(int(singletonLockFile.Fd()), syscall.LOCK_UN)
		_ = singletonLockFile.Close()
		_ = os.Remove(singletonLockFile.Name())
		singletonLockFile = nil
	}
}
