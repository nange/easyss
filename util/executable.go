package util

import (
	"os"
	"path/filepath"
)

// 解析符号链接以保证多次启动结果稳定（macOS 的 Finder/launchd 经符号链接的 bundle 路径启动）；
// 无法解析时回退到 os.Executable 的原始结果。
func ExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		return real, nil
	}
	return exe, nil
}
