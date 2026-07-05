//go:build !windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/nange/easyss/v3/log"
)

func runDaemon() {
	exe, _ := os.Executable()

	// Build args for child process, stripping --daemon* flags and appending --daemon=false
	// to prevent infinite daemonization loops.
	var args []string
	skipNext := false
	for _, arg := range os.Args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "--daemon" {
			continue
		}
		if strings.HasPrefix(arg, "--daemon=") {
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
