//go:build darwin && !headless

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nange/easyss/v3/util"
)

const launchAgentPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.github.nange.easyss</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
</dict>
</plist>
`

func launchAgentPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", "com.github.nange.easyss.plist"), nil
}

func enableAutoStart() error {
	// 解析符号链接后的路径使 plist 在多次启动间保持稳定
	// （Finder/launchd 通过符号链接的 bundle 路径启动应用），
	// 并让 isAutoStartEnabled 能与这里写入的确切字符串比较。
	exePath, err := util.ExecutablePath()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	plistPath, err := launchAgentPath()
	if err != nil {
		return fmt.Errorf("resolve plist path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(plistPath), 0755); err != nil {
		return fmt.Errorf("mkdir LaunchAgents: %w", err)
	}

	plistContent := fmt.Sprintf(launchAgentPlist, exePath)
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	// 只写 plist——绝不用 launchctl 加载它。
	// launchctl load 会立即启动第二个实例，导致托盘图标重复。
	// plist 带有 RunAtLoad=true，macOS 会在下次登录时自动启动应用。
	return nil
}

func disableAutoStart() error {
	plistPath, err := launchAgentPath()
	if err != nil {
		return fmt.Errorf("resolve plist path: %w", err)
	}

	// 从当前会话卸载该 job。
	unloadCmd := exec.Command("launchctl", "unload", plistPath)
	if out, err := unloadCmd.CombinedOutput(); err != nil {
		// job 当前未加载也没关系。
		_ = string(out)
	}

	// 删除 plist 文件。
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}

	return nil
}

func isAutoStartEnabled() bool {
	plistPath, err := launchAgentPath()
	if err != nil {
		return false
	}

	data, err := os.ReadFile(plistPath)
	if err != nil {
		return false
	}

	// 检查 plist 是否引用当前可执行文件路径。
	exePath, err := util.ExecutablePath()
	if err != nil {
		return false
	}

	return strings.Contains(string(data), exePath)
}
