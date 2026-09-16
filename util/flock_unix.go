//go:build !windows

package util

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// FlockTry 在 f 上以非阻塞方式获取排他锁 flock。返回非 nil 错误
// 意味着另一个进程持有该锁（或 flock 调用失败）。进程退出时
// 内核会释放该锁，包括被 kill -9 杀死的情况。
func FlockTry(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

// FlockWait 在 f 上获取排他锁 flock，重试直至成功获取锁
// 或超时到期。用于锁持有者可能仍在清理的场景：被 kill -9 杀死的
// 前持有者只有在内核回收它之后才会释放锁。
func FlockWait(f *os.File, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for lock after %v", timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Unflock 释放 f 上的排他锁 flock。
func Unflock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
