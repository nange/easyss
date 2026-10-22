//go:build linux

package tunhelper

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"
)

// Spawn 通过 pkexec 启动一个常驻的提权 TUN helper 进程；完整生命周期见
// spawnTunHelper。
func Spawn(httpAddr string, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	// Linux 使用抽象 socket（@ 前缀）：它没有文件系统条目（无需清理陈旧文件、无需
	// chmod），也不受 pkexec 挂载命名空间隔离的影响。
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
	}, httpAddr, fdSocketPath, logFile, logLevel, timeout)
}
