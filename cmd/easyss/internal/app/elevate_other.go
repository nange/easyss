//go:build !windows

package app

// elevateRestart 在 darwin/linux 上不可用：那里由 tunUpAuto 用 pkexec/osascript 原地提权，
// 不需要跨进程重启。
func elevateRestart(*App) error { return errElevationUnsupported }
