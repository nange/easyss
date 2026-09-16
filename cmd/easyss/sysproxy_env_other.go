//go:build !linux && !headless

package main

// setSysProxyEnv 在 Linux 之外是空操作：macOS 和 Windows 有真正的
// 系统级代理配置，sysproxy 包已经会更新它，而且那里的浏览器确实会遵守它。
func setSysProxyEnv(_ int) (bool, error) {
	return false, nil
}

func unsetSysProxyEnv() (bool, error) {
	return false, nil
}
