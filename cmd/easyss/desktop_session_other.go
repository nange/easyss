//go:build !headless && !linux

package main

// 桌面会话交接只在 Linux 上存在：pkexec/sudo 丢失会话环境是 Linux 桌面特有的。
func sessionLaunch(argv []string) []string { return argv }
