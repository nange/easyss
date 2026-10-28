//go:build windows

package tunhelper

import (
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/sys/windows"
)

// IsRoot 报告当前进程是否持有管理员令牌。Windows 没有 root，主程序以 asInvoker 启动后
// 就建不了 TUN 设备，只有用户授权提权（或账户本身已在提权状态）时才拿得到。
func IsRoot() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Spawn 在此平台不受支持：Windows 的提权路径是"整个进程以管理员权限重启"，
// 没有 fd 传递，也不会有 helper 子进程。
func Spawn(httpAddr string, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	return nil, nil, fmt.Errorf("SpawnTunHelper is not supported on this platform")
}
