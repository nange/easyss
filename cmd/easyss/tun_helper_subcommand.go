package main

import (
	"flag"
	"os"
)

// runTunHelperSubcommand 处理内部的 "tun-helper" 子命令：以特权辅助进程的身份运行本
// 二进制，返回子命令是否已被处理（若已处理，进程此时已经退出）。pkexec/osascript 会
// 剥离环境变量，引导参数无法自行推导，因此通过子命令标志传入。
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
