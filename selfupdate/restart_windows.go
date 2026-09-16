//go:build windows

package selfupdate

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/nange/easyss/v3/log"
)

// restartRetries 和 restartRetryDelay 让 Restart 能容忍瞬时的
// CreateProcess 失败（例如杀毒软件仍在扫描刚就位的二进制）。
const (
	restartRetries    = 3
	restartRetryDelay = 500 * time.Millisecond
)

// Restart 在一个隐藏窗口中，用原始参数重新启动刚安装的二进制。安装步骤
// 完成后，原路径已指向新二进制，因此只需重新解析 os.Executable 即可。
//
// 这里使用 os.StartProcess 而非 exec.Command/exec.Cmd：在 Windows 上，
// exec 包会通过 LookPath/lookExtensions 解析命令，它只接受带 PATHEXT
// 扩展名的可执行文件，因此即使文件存在，没有 ".exe" 后缀的二进制也会被
// 拒绝。os.StartProcess 会把完整路径直接交给 CreateProcess。子进程的
// 标准句柄被重定向到 NUL（与 exec.Command 的做法一致），因此父进程的
// 句柄永远不会被继承。Restart 返回 nil 后，调用方必须终止当前进程。
func Restart() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open nul device: %w", err)
	}
	defer func() { _ = devNull.Close() }()

	args := append([]string{exe}, restartArgs()...)
	attr := &os.ProcAttr{
		Files: []*os.File{devNull, devNull, devNull},
		Sys:   &syscall.SysProcAttr{HideWindow: true},
	}

	var proc *os.Process
	for attempt := 0; attempt <= restartRetries; attempt++ {
		proc, err = os.StartProcess(exe, args, attr)
		if err == nil {
			break
		}
		if attempt < restartRetries {
			log.Warn("[UPDATE] restart attempt failed, retrying", "path", exe, "err", err)
			time.Sleep(restartRetryDelay)
		}
	}
	if err != nil {
		if info, statErr := os.Stat(exe); statErr == nil {
			log.Error("[UPDATE] restart failed", "path", exe, "size", info.Size(), "err", err)
		} else {
			log.Error("[UPDATE] restart failed", "path", exe, "statErr", statErr, "err", err)
		}
		return err
	}
	_ = proc.Release()
	return nil
}
