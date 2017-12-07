package main

import (
	"os"
	"os/exec"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func daemon() {
	if *godaemon {
		args := os.Args[1:]
		args = append(args, "-daemon=false")
		cmd := exec.Command(os.Args[0], args...)
		//cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Start()
		log.Info("[PID]:", cmd.Process.Pid)
		os.Exit(0)
	}
}
