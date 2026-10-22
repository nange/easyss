//go:build !windows

package app

import "syscall"

// addrInUseTestErr 返回当前平台 net 包真实会包装的“端口占用”错误。
func addrInUseTestErr() error { return syscall.EADDRINUSE }
