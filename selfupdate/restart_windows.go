//go:build windows

package selfupdate

import (
	"os"
	"os/exec"
	"syscall"
)

// Restart relaunches the freshly installed binary with the original
// arguments in a hidden window. After the install step the original path
// points at the new binary, so re-resolving os.Executable is enough. The
// caller must terminate the current process once Restart returns nil.
func Restart() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, restartArgs()...) //nolint:gosec // relaunching ourselves by design
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	return cmd.Start()
}
