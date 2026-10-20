//go:build darwin

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SpawnTunHelper 通过带管理员权限的 osascript 启动一个常驻的提权 TUN helper 进程；
// 完整生命周期见 spawnTunHelper。
func SpawnTunHelper(httpAddr string, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	// macOS 没有抽象 Unix socket：fd socket 是文件系统条目，必须在 listen 前清理陈旧
	// 文件，并在之后让提权的（root）helper 可以访问。
	return spawnTunHelper(tunHelperElevator{
		label: "osascript",
		command: func(innerCmd string) *exec.Cmd {
			scriptCmd := strings.ReplaceAll(innerCmd, "\"", "\\\"")
			script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", scriptCmd)
			return exec.Command("osascript", "-e", script)
		},
		innerCmd: func(exe, helperArgs, fifoPath string) string {
			return fmt.Sprintf("'%s' %s < '%s' &>/dev/null &", exe, helperArgs, fifoPath)
		},
		beforeListen: func(fdSocketPath string) {
			os.Remove(fdSocketPath) //nolint:errcheck
		},
		afterListen: func(fdSocketPath string) {
			// 确保提权的 helper（root）可以访问该 socket。
			os.Chmod(fdSocketPath, 0666) //nolint:errcheck
		},
		cleanupSocket: func(fdSocketPath string) {
			os.Remove(fdSocketPath) //nolint:errcheck
		},
	}, httpAddr, fdSocketPath, logFile, logLevel, timeout)
}
