//go:build !windows

package selfupdate

import (
	"os"
	"os/exec"
	"syscall"
)

// Restart 在一个脱离（detached）的进程中，用原始参数重新启动刚安装的
// 二进制。安装步骤完成后，原路径已指向新二进制（或 bundle），因此只需
// 重新解析 os.Executable 即可。Restart 返回 nil 后，调用方必须终止当前进程。
func Restart() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, restartArgs()...) //nolint:gosec // relaunching ourselves by design
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // 脱离控制终端
	}
	return cmd.Start()
}
