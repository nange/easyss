package main

import (
	"flag"
	"os"
)

// runTunHelperSubcommand 处理内部的 "tun-helper" 子命令：以特权 TUN 辅助进程的
// 身份运行本二进制（由托盘进程通过 pkexec/osascript 启动）。它返回子命令是否已被
// 处理；若已处理，进程此时已经退出。
//
// 该辅助进程是一个长期运行的特权进程：打开 TUN 设备、设置路由/DNS、通过 Unix
// 套接字把 fd 传回父进程，并持续监听 stdin 上的父进程生命周期信号。引导参数
// （从哪里获取 TUN 配置、把 fd 发往哪里）无法由辅助进程自行推导——pkexec/
// osascript 会剥离环境变量——因此它们通过子命令标志传入。
func runTunHelperSubcommand() bool {
	if len(os.Args) < 2 || os.Args[1] != "tun-helper" {
		return false
	}

	fs := flag.NewFlagSet("tun-helper", flag.ExitOnError)
	var tunHTTPAddr, tunFDSocket, logFile, logLevel string
	fs.StringVar(&tunHTTPAddr, "tun-http-addr", "", "HTTP address of the parent process to fetch config from")
	fs.StringVar(&tunFDSocket, "tun-fd-socket", "", "Unix socket path for fd passing to parent")
	fs.StringVar(&logFile, "log-file", "", "log file path")
	fs.StringVar(&logLevel, "log-level", "", "log level (debug, info, warn, error)")
	_ = fs.Parse(os.Args[2:])

	os.Exit(runTunHelper(tunHTTPAddr, tunFDSocket, logFile, logLevel))
	return true
}
