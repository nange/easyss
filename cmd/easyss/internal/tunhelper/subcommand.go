package tunhelper

import (
	"flag"
	"os"
)

// RunSubcommand 处理内部的 "tun-helper" 子命令：以特权辅助进程的身份运行本
// 二进制，返回子命令是否已被处理（若已处理，进程此时已经退出）。pkexec/osascript 会
// 剥离环境变量，引导参数无法自行推导，因此通过子命令标志传入。
func RunSubcommand() bool {
	if len(os.Args) < 2 || os.Args[1] != "tun-helper" {
		return false
	}

	fs := flag.NewFlagSet("tun-helper", flag.ExitOnError)
	var tunHTTPAddr, tunFDSocket, logFile, logLevel string
	fs.StringVar(&tunHTTPAddr, "tun-http-addr", "", "父进程的 HTTP 地址，用于拉取配置")
	fs.StringVar(&tunFDSocket, "tun-fd-socket", "", "向父进程传递 fd 的 Unix socket 路径")
	fs.StringVar(&logFile, "log-file", "", "日志文件路径")
	fs.StringVar(&logLevel, "log-level", "", "日志级别（debug、info、warn、error）")
	_ = fs.Parse(os.Args[2:])

	os.Exit(runTunHelper(tunHTTPAddr, tunFDSocket, logFile, logLevel))
	return true
}
