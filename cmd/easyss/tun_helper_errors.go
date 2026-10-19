package main

import "errors"

// errTunHelperStartup 标记提权器在 TUN helper 真正启动之前退出。最常见的原因是
// 用户在 pkexec/osascript 对话框里取消授权——这是用户意图而不是故障，因此托盘
// 不弹通知。它是跨平台哨兵（root_unix.go 只在 darwin/linux 编译），调用方用
// errors.Is 判定，不再匹配错误文本。
var errTunHelperStartup = errors.New("tun helper exited before startup")
