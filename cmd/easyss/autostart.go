//go:build !headless

package main

// EnableAutoStart 注册应用随用户登录自动启动。
func EnableAutoStart() error {
	return enableAutoStart()
}

// DisableAutoStart 取消注册应用随用户登录自动启动。
func DisableAutoStart() error {
	return disableAutoStart()
}

// IsAutoStartEnabled 检查应用是否已注册为登录时自动启动。
func IsAutoStartEnabled() bool {
	return isAutoStartEnabled()
}
