package easyss

import (
	"os"
	"os/exec"

	"github.com/nange/easyss/v2/log"
)

func Daemon(godaemon bool) {
	if godaemon {
		args := os.Args[1:]
		args = append(args, "-daemon=false")
		cmd := exec.Command(os.Args[0], args...)
		if err := cmd.Start(); err != nil {
			log.Error("startup easyss failed", "err", err)
			os.Exit(1)
		}
		log.Info("easyss has been started, now you can close this window", "pid", cmd.Process.Pid)
		os.Exit(0)
	}
}
