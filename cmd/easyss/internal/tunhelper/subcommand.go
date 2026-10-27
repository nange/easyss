package tunhelper

import (
	"flag"
	"os"
)

// helperOptions 是 tun-helper 子命令的启动参数。各平台只使用其中一部分：
// darwin/linux 用 fdSocketPath 接收 TUN fd，Windows 用 controlAddr/controlToken 与父进程
// 建立控制通道并由 helper 自己运行 tun2socks。
type helperOptions struct {
	httpAddr     string
	fdSocketPath string
	controlAddr  string
	controlToken string
	logFile      string
	logLevel     string
}

// RunSubcommand 处理内部的 "tun-helper" 子命令：以特权辅助进程的身份运行本
// 二进制，返回子命令是否已被处理（若已处理，进程此时已经退出）。pkexec/osascript 会
// 剥离环境变量，引导参数无法自行推导，因此通过子命令标志传入。
func RunSubcommand() bool {
	if len(os.Args) < 2 || os.Args[1] != "tun-helper" {
		return false
	}

	fs := flag.NewFlagSet("tun-helper", flag.ExitOnError)
	var opts helperOptions
	fs.StringVar(&opts.httpAddr, "tun-http-addr", "", "HTTP address of the parent process to fetch config from")
	fs.StringVar(&opts.fdSocketPath, "tun-fd-socket", "", "Unix socket path for fd passing to parent")
	fs.StringVar(&opts.controlAddr, "tun-control-addr", "", "Windows: loopback control address of the parent process")
	fs.StringVar(&opts.controlToken, "tun-control-token", "", "Windows: one-time token for the control connection")
	fs.StringVar(&opts.logFile, "log-file", "", "log file path")
	fs.StringVar(&opts.logLevel, "log-level", "", "log level (debug, info, warn, error)")
	_ = fs.Parse(os.Args[2:])

	os.Exit(runTunHelper(opts))
	return true
}
