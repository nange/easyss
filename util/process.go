package util

import (
	"errors"
	"os/exec"
)

// StartDetached 启动一个命令，并在其被创建后立即返回：
// 交互式终端只要用户保持窗口打开就会一直停留在前台，因此等待它结束
// （就像 Command 那样）会阻塞调用方整个会话。进程在后台被回收，
// 以避免留下僵尸进程。
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
