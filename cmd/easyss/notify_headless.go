//go:build headless

package main

// notifyConfigError 在 headless 构建中是空操作：没有系统托盘可显示
// 通知，且调用方已经记录启动错误。
func notifyConfigError(error) {}
