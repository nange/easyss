//go:build !windows

package app

import (
	"errors"
	"syscall"
)

// isAddrInUse 判断错误是否为"端口已被占用"的绑定失败。Unix 的 net 错误会
// 包装 syscall.EADDRINUSE，直接用 errors.Is；不再匹配平台错误文本。
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}
