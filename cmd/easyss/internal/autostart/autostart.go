//go:build !headless

package autostart

// EnableAutoStart 注册应用随用户登录自动启动。
func EnableAutoStart() error {
	return enableAutoStart()
}

// DisableAutoStart 取消注册应用随用户登录自动启动。
func DisableAutoStart() error {
	return disableAutoStart()
}

// IsAutoStartEnabled 检查应用是否已注册为登录时自动启动；Run 值仍指向本程序、
// 但字面路径过时时会顺手改写它，因此调用方不要当成纯读操作。
func IsAutoStartEnabled() bool {
	return isAutoStartEnabled()
}
