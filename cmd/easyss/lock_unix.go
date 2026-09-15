//go:build !headless && (darwin || linux)

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/nange/easyss/v3/log"
)

var singletonLockFile *os.File

// tryAcquireSingletonLock attempts to acquire the exclusive file lock that
// ensures only one instance of the app runs at a time. It returns
// errAnotherInstance when another process holds the lock, or the underlying
// error (e.g. the lock file cannot be created) otherwise.
func tryAcquireSingletonLock() error {
	lockPath := filepath.Join(os.TempDir(), fmt.Sprintf("easyss-%d.lock", os.Getuid()))

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return errAnotherInstance
	}

	// Write PID for diagnostic purposes.
	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())

	singletonLockFile = f
	return nil
}

// acquireSingletonLock acquires the singleton lock, exiting the process when
// the lock is unavailable. Must be called after daemonization.
func acquireSingletonLock() {
	err := tryAcquireSingletonLock()
	switch {
	case err == nil:
		return
	case errors.Is(err, errAnotherInstance):
		log.Warn("[EASYSS-V3] another instance is already running, exiting")
		os.Exit(0)
	default:
		log.Error("[EASYSS-V3] failed to open lock file", "err", err)
		os.Exit(1)
	}
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
