package util

import (
	"errors"
	"os/exec"
)

// 交互式终端只要窗口不关就会一直停在前台，等待它结束会阻塞调用方整个会话；
// 进程由后台 goroutine 回收，避免留下僵尸进程。
func StartDetached(argv []string) error {
	if len(argv) == 0 {
		return errors.New("empty command")
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_ = cmd.Wait()
	}()

	return nil
}
