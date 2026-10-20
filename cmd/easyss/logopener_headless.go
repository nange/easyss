//go:build headless

package main

// headless 构建没有托盘与日志菜单，日志查看器不会被使用。
func defaultLogOpener() logOpener { return logOpener{} }
