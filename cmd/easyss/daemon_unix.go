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
	"github.com/nange/easyss/v3/util"
)

func runDaemon() {
	lockPath := filepath.Join(os.TempDir(), fmt.Sprintf("easyss-%d.lock", os.Getuid()))
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		log.Error("[EASYSS-V3] daemon lock check failed", "err", err)
		os.Exit(1)
	}
	if err := util.FlockTry(f); err != nil {
		log.Info("[EASYSS-V3] daemon already running, exiting")
		_ = f.Close()
		os.Exit(0)
	}
	_ = util.Unflock(f)
	_ = f.Close()

	exe, _ := util.ExecutablePath()

	// 构建子进程参数：剔除 -daemon/--daemon 标志并追加
	// --daemon=false，防止无限守护化循环。
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
		Setsid: true, // 创建新会话，脱离控制终端
	}
	// Stdin/Stdout/Stderr 为 nil -> /dev/null，避免绑定到终端

	if err := cmd.Start(); err != nil {
		log.Error("[EASYSS-V3] daemon start", "err", err)
		os.Exit(1)
	}
	log.Info("[EASYSS-V3] daemon started", "pid", cmd.Process.Pid)
	os.Exit(0)
}
