//go:build !headless && !darwin && !linux && !windows

package main

// tryAcquireSingletonLock 在没有锁实现平台的空操作：应用在无单实例保护
// 的情况下运行，与其它平台回退文件一致（root_fallback.go、autostart_other.go）。
func tryAcquireSingletonLock() error { return nil }

// acquireSingletonLock 是空操作（见 tryAcquireSingletonLock）。
func acquireSingletonLock() {}

// releaseSingletonLock 是空操作（见 tryAcquireSingletonLock）。
func releaseSingletonLock() {}
