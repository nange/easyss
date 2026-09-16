//go:build !darwin && !linux

package main

import (
	"fmt"
	"os"
)

// runTunHelper 在非 darwin/linux 平台上不支持 TUN 辅助进程：
// 打印错误信息到 stderr 并返回退出码 1。
func runTunHelper(httpAddr, fdSocketPath, logFilePath, logLevel string) int {
	fmt.Fprintln(os.Stderr, "tun helper is only supported on darwin/linux")
	return 1
}
