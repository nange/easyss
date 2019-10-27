package easyss

import (
	"os"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

func Daemon(godaemon bool) {
	if godaemon {
		args := os.Args[1:]
		args = append(args, "-daemon=false")
		cmd := exec.Command(os.Args[0], args...)
		if err := cmd.Start(); err != nil {
			log.Errorf("startup easyss failed. err:%v", err)
			os.Exit(1)
		}
		log.Infof("easyss have been started. [PID]:%v, now you can close this window", cmd.Process.Pid)
		os.Exit(0)
	}
}
