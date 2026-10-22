//go:build windows

package app

func runDaemon() {
	// Windows 不支持守护模式。
	// run.go 中的调用方已用 runtime.GOOS != "windows" 守护。
}
