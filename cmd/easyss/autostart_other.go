//go:build !windows && !darwin && !linux && !headless

package main

// 在不支持的平台上，自启动是空操作。托盘菜单项仍然出现，
// 但处于禁用状态（始终未勾选且无功能）。

func enableAutoStart() error {
	return nil
}

func disableAutoStart() error {
	return nil
}

func isAutoStartEnabled() bool {
	return false
}
