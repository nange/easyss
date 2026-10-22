//go:build !headless && !darwin && !linux && !windows

package singleton

// TryAcquire 在没有锁实现平台的空操作：应用在无单实例保护
// 的情况下运行，与其它平台回退文件一致（tunhelper/spawn_other.go、autostart/autostart_other.go）。
func TryAcquire() error { return nil }

// Acquire 是空操作（见 TryAcquire）。
func Acquire() {}

// Release 是空操作（见 TryAcquire）。
func Release() {}
