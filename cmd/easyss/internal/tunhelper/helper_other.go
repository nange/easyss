//go:build !darwin && !linux && !windows

package tunhelper

import (
	"fmt"
	"os"
)

// runTunHelper 在既没有 unix 提权流程、也没有 Windows helper 的平台上不支持 TUN 辅助进程：
// 打印错误信息到 stderr 并返回退出码 1。
func runTunHelper(helperOptions) int {
	fmt.Fprintln(os.Stderr, "tun helper is only supported on darwin/linux/windows")
	return 1
}
