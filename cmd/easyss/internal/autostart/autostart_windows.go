//go:build windows && !headless

package autostart

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/windows/registry"
)

const (
	autoStartRunKey  = `Software\Microsoft\Windows\CurrentVersion\Run`
	autoStartValName = `Easyss`
)

func enableAutoStart() error {
	exe, err := util.ExecutablePath()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	// CreateKey 在 Run 键被清理工具删掉时也能恢复；OpenKey 会直接失败。
	key, _, err := registry.CreateKey(registry.CURRENT_USER, autoStartRunKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer func() { _ = key.Close() }()

	if err := key.SetStringValue(autoStartValName, runValue(exe)); err != nil {
		return fmt.Errorf("set registry value: %w", err)
	}

	return nil
}

func disableAutoStart() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, autoStartRunKey, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer func() { _ = key.Close() }()

	if err := key.DeleteValue(autoStartValName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("delete registry value: %w", err)
	}

	return nil
}

func isAutoStartEnabled() bool {
	exe, err := util.ExecutablePath()
	if err != nil {
		return false
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, autoStartRunKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer func() { _ = key.Close() }()

	val, _, err := key.GetStringValue(autoStartValName)
	if err != nil {
		return false
	}

	// 兼容旧版本写入的未加引号路径：升级后复选框不应假装从未启用过。
	return strings.Trim(val, `"`) == exe
}

// runValue 是 Run 键的 command line。路径本身不可能包含双引号，因此只需整体包一层；
// 不加引号的带空格路径交给 ShellExecute 解析时会先尝试 "C:\Program.exe" 之类的中间名。
func runValue(exe string) string {
	return `"` + exe + `"`
}
