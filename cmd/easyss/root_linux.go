//go:build linux

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"
)

// SpawnTunHelper 通过 pkexec 启动一个常驻的提权 TUN helper 进程。
// 它创建一个 FIFO 用于生命周期信号（关闭写端触发 helper 退出），以及
// 一个用于接收 TUN 文件描述符的 Unix socket。完整生命周期见
// spawnTunHelper。
//
// 返回：
//   - fifoWriter：关闭以通知 helper 关闭
//   - fdListener：接受连接并调用 ReceiveFd 获取 TUN fd
func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	// Linux 使用抽象 socket（@ 前缀）：它没有文件系统条目
	// （无需清理陈旧文件、无需 chmod），也不受 pkexec 挂载
	// 命名空间隔离的影响。
	return spawnTunHelper(tunHelperElevator{
		label: "pkexec",
		command: func(innerCmd string) *exec.Cmd {
			// 传入 HOME，使 helper 能找到配置文件；pkexec 会净化环境变量。
			cmdArgs := []string{"env"}
			if home := os.Getenv("HOME"); home != "" {
				cmdArgs = append(cmdArgs, fmt.Sprintf("HOME=%s", home))
			}
			cmdArgs = append(cmdArgs, "sh", "-c", innerCmd)
			return exec.Command("pkexec", cmdArgs...)
		},
		innerCmd: func(exe, helperArgs, fifoPath string) string {
			return fmt.Sprintf("nohup '%s' %s < '%s' >/dev/null 2>&1 &", exe, helperArgs, fifoPath)
		},
	}, httpPort, fdSocketPath, logFile, logLevel, timeout)
}
