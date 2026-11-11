//go:build windows && !headless

package autostart

import (
	"errors"
	"fmt"
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
	if !sameExecutable(val, exe) {
		return false
	}

	// 值指向的还是本程序、但字面路径已过时（换了构建产物或改了安装目录）时改写，
	// 否则旧文件被删掉以后登录自启会静默失效。
	if val != runValue(exe) {
		rewriteRunValue(exe)
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

// sameExecutable 除大小写外还忽略扩展名：`make easyss` 的产物 bin/easyss 没有
// 扩展名，os.Executable 返回的路径也就不带 .exe，而登录时系统会解析到同名 .exe。
func sameExecutable(stored, exe string) bool {
	stored, exe = filepath.Clean(runExe(stored)), filepath.Clean(exe)
	return strings.EqualFold(stored, exe) || strings.EqualFold(trimExe(stored), trimExe(exe))
}

func trimExe(path string) string {
	if len(path) > 4 && strings.EqualFold(path[len(path)-4:], ".exe") {
		return path[:len(path)-4]
	}
	return path
}
