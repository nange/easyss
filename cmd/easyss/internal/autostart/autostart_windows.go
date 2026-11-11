//go:build windows && !headless

package autostart

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

	if err := key.SetStringValue(autoStartValName, runValue(canonicalRunExe(exe))); err != nil {
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
	want := canonicalRunExe(exe)
	if !sameExecutable(val, want) {
		return false
	}

	// 只改写"值就是一个路径"的情况：替换整个值会静默丢掉用户追加的参数（-c 之类）。
	if isBarePathValue(val) && val != runValue(want) {
		rewriteRunValue(want)
	}

	return true
}

// runValue 是 Run 键的 command line。路径本身不可能包含双引号，因此只需整体包一层；
// 不加引号的带空格路径交给 ShellExecute 解析时会先尝试 "C:\Program.exe" 之类的中间名。
func runValue(exe string) string {
	return `"` + exe + `"`
}

func rewriteRunValue(exe string) {
	key, err := registry.OpenKey(registry.CURRENT_USER, autoStartRunKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer func() { _ = key.Close() }()

	_ = key.SetStringValue(autoStartValName, runValue(exe))
}

// runExe 取 Run 值里的可执行文件路径：我们自己只写带引号的单个路径，
// 但旧版本或用户手动改过的值可能没有引号，或带着参数。
func runExe(value string) string {
	v := strings.TrimSpace(value)
	if !strings.HasPrefix(v, `"`) {
		return v
	}
	if i := strings.IndexByte(v[1:], '"'); i >= 0 {
		return v[1 : i+1]
	}
	return v[1:]
}

// sameExecutable 做规范化后比较：大小写、无扩展名产物与同名 .exe 的差异都不影响判断
// （`make easyss` 的 bin/easyss 只有交给 ShellExecute 才会落到 .exe 上）。
func sameExecutable(stored, exe string) bool {
	return strings.EqualFold(
		canonicalRunExe(filepath.Clean(runExe(stored))),
		canonicalRunExe(filepath.Clean(exe)),
	)
}

// canonicalRunExe 优先返回真实存在的同名 .exe：无扩展名的路径要靠 ShellExecute 按
// PATHEXT 解析，同目录的 .com/.bat 会被优先匹配，.exe 才是精确路径。
func canonicalRunExe(path string) string {
	if strings.EqualFold(filepath.Ext(path), ".exe") {
		return path
	}
	if info, err := os.Stat(path + ".exe"); err == nil && !info.IsDir() {
		return path + ".exe"
	}
	return path
}

// isBarePathValue 判断 Run 值是否只有一个路径：带参数的值由用户维护，整体替换会丢参数。
func isBarePathValue(value string) bool {
	v := strings.TrimSpace(value)
	return strings.EqualFold(v, runValue(runExe(v)))
}
