package selfupdate

import (
	"os"
	"strings"
)

// restartArgs 重建原始命令行：去掉 daemon 标志并追加 --daemon=false，
// 使新进程不会再次守护化（daemonize）。"-daemon value" 和 "-daemon=value"
// 两种写法都会被移除。
func restartArgs() []string {
	var args []string
	skipNext := false
	for _, arg := range os.Args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		switch {
		case arg == "-daemon" || arg == "--daemon":
			skipNext = true // 丢弃以空格分隔的布尔值
		case strings.HasPrefix(arg, "-daemon=") || strings.HasPrefix(arg, "--daemon="):
		default:
			args = append(args, arg)
		}
	}
	return append(args, "--daemon=false")
}
