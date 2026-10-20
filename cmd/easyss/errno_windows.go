//go:build windows

package main

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// isAddrInUse 判断错误是否为"端口已被占用"的绑定失败。Windows 的 net 错误
// 包装的是 WSAEADDRINUSE（10048），而不是 Unix 的 syscall.EADDRINUSE；两者都
// 检查以兼容手工构造/包装的 Errno。
func isAddrInUse(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) ||
		errors.Is(err, syscall.EADDRINUSE)
}
