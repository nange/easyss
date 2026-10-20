//go:build windows

package selfupdate

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/nange/easyss/v3/log"
)

// restartRetries/restartRetryDelay 让 Restart 容忍瞬时的 CreateProcess 失败
// （例如杀毒软件仍在扫描刚就位的二进制）。
const (
	restartRetries    = 3
	restartRetryDelay = 500 * time.Millisecond
)

// 返回 nil 后调用方必须终止当前进程。用 os.StartProcess 而非 exec.Command：Windows 的 exec
// 只接受带 PATHEXT 扩展名的文件，无 ".exe" 后缀的二进制会被拒绝；子进程句柄重定向到 NUL。
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
