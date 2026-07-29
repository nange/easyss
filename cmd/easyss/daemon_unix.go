//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nange/easyss/v3/log"
)

func runDaemon() {
	lockPath := filepath.Join(os.TempDir(), fmt.Sprintf("easyss-%d.lock", os.Getuid()))
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		log.Error("[EASYSS-V3] daemon lock check failed", "err", err)
		os.Exit(1)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		log.Info("[EASYSS-V3] daemon already running, exiting")
		_ = f.Close()
		os.Exit(0)
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()

	exe, _ := os.Executable()

	// Build args for child process, stripping -daemon/--daemon flags and appending
	// --daemon=false to prevent infinite daemonization loops.
	var args []string
	for _, arg := range os.Args[1:] {
		if arg == "-daemon" || arg == "--daemon" {
			continue
		}
		if strings.HasPrefix(arg, "-daemon=") || strings.HasPrefix(arg, "--daemon=") {
			continue
		}
		args = append(args, arg)
	}
	args = append(args, "--daemon=false")

	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // Create a new session, detach from controlling terminal
	}
	// Stdin/Stdout/Stderr nil -> /dev/null, prevents binding to the terminal

	if err := cmd.Start(); err != nil {
		log.Error("[EASYSS-V3] daemon start", "err", err)
		os.Exit(1)
	}
	log.Info("[EASYSS-V3] daemon started", "pid", cmd.Process.Pid)
	os.Exit(0)
}
