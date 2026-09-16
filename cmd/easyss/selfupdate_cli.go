package main

import (
	"os"

	"github.com/nange/easyss/v3/selfupdate"
)

// runSelfupdateSubcommand 处理 "selfupdate" 子命令（检查最新 release，
// 默认情况下下载并原地替换正在运行的二进制，且不重启进程）。
// 返回值表示该子命令是否已被处理；若已处理，则进程已经退出。
func runSelfupdateSubcommand() bool {
	if len(os.Args) < 2 || os.Args[1] != "selfupdate" {
		return false
	}
	os.Exit(selfupdate.RunCLICommand(os.Args[2:], selfupdateProduct()))
	return true
}
