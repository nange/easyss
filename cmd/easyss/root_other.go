//go:build !darwin && !linux

package main

import (
	"fmt"
	"io"
	"net"
	"time"
)

// IsRoot 报告进程是否以管理员权限运行。在没有 unix 提权流程的平台上，
// 该检查被绕过（返回 true），从而使用直接的 TUN 路径。
func IsRoot() bool {
	return true
}

// SpawnTunHelper 在此平台不受支持：提权 helper 流程只存在于 darwin/linux。
func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	return nil, nil, fmt.Errorf("SpawnTunHelper is not supported on this platform")
}
