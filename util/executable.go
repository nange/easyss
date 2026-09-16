package util

import (
	"os"
	"path/filepath"
)

// ExecutablePath 返回当前可执行文件的真实路径，会解析符号链接，
// 以保证多次启动时结果稳定（macOS 的 Finder/launchd 通过符号链接的
// bundle 路径启动）。当符号链接无法解析时，回退到
// os.Executable 的原始结果。
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
