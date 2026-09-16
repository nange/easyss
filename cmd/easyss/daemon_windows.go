//go:build windows

package main

func runDaemon() {
	// Windows 不支持守护模式。
	// start.go 中的调用方已用 runtime.GOOS != "windows" 守护。
}
