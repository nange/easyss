//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isAddrInUse 判断错误是否为"端口已被占用"的绑定失败。Windows 的 net 错误
// 包装的是 WSAEADDRINUSE（10048）；syscall.EADDRINUSE 在 Windows 上只是 Go
// 合成的 APPLICATION_ERROR 常量，net 不会返回它。
func isAddrInUse(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE)
}
