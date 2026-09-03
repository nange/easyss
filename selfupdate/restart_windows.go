//go:build windows

package selfupdate

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/nange/easyss/v3/log"
)

// restartRetries and restartRetryDelay make Restart tolerant of transient
// CreateProcess failures (e.g. antivirus still scanning the freshly placed
// binary).
const (
	restartRetries    = 3
	restartRetryDelay = 500 * time.Millisecond
)

// Restart relaunches the freshly installed binary with the original
// arguments in a hidden window. After the install step the original path
// points at the new binary, so re-resolving os.Executable is enough.
//
// os.StartProcess is used instead of exec.Command/exec.Cmd: on Windows the
// exec package resolves the command through LookPath/lookExtensions, which
// only accepts executables with a PATHEXT extension, so a binary named
// without ".exe" would be rejected even though the file exists.
// os.StartProcess hands the full path straight to CreateProcess. The
// child's standard handles are routed to NUL (as exec.Command would do) so
// the parent's handles are never inherited. The caller must terminate the
// current process once Restart returns nil.
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
