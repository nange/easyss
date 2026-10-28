//go:build !darwin && !linux && !windows

package tunhelper

import (
	"fmt"
	"io"
	"net"
	"time"
)

// IsRoot 报告进程是否以管理员权限运行。这些平台既没有 unix 提权流程，也没有 UAC，
// 该检查被绕过（返回 true），从而使用直接的 TUN 路径。
func IsRoot() bool {
	return true
}

// Spawn 在此平台不受支持：提权 helper 流程只存在于 darwin/linux。
func Spawn(httpAddr string, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	return nil, nil, fmt.Errorf("SpawnTunHelper is not supported on this platform")
}
