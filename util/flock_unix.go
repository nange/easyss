//go:build !windows

package util

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// FlockTry acquires an exclusive flock on f without blocking. A non-nil error
// means another process holds the lock (or the flock failed). The lock is
// released by the kernel when the process exits, including on kill -9.
func FlockTry(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

// FlockWait acquires an exclusive flock on f, retrying until the lock is
// acquired or the timeout expires. Used where the lock holder may still be
// cleaning up: a previous holder that was killed -9 releases the lock only
// when the kernel reaps it.
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

// Unflock releases the exclusive flock on f.
func Unflock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
