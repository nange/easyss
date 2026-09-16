//go:build !headless && (darwin || linux)

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

var singletonLockFile *os.File

// tryAcquireSingletonLock 尝试获取确保同一时刻只运行一个应用实例的
// 排他文件锁。当另一个进程持有该锁时返回 errAnotherInstance，
// 否则返回底层错误（例如无法创建锁文件）。
func tryAcquireSingletonLock() error {
	lockPath := filepath.Join(os.TempDir(), fmt.Sprintf("easyss-%d.lock", os.Getuid()))

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}

	if err := util.FlockTry(f); err != nil {
		_ = f.Close()
		return errAnotherInstance
	}

	// 写入 PID 供诊断使用。
	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())

	singletonLockFile = f
	return nil
}

// acquireSingletonLock 获取单实例锁，锁不可用时退出进程。
// 必须在守护化之后调用。
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

// releaseSingletonLock 释放文件锁并清理锁文件。
func releaseSingletonLock() {
	if singletonLockFile != nil {
		_ = util.Unflock(singletonLockFile)
		_ = singletonLockFile.Close()
		_ = os.Remove(singletonLockFile.Name())
		singletonLockFile = nil
	}
}
