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
	// The symlink-resolved path keeps the plist stable across launches
	// (Finder/launchd start the app through a symlinked bundle path) and lets
	// isAutoStartEnabled compare against the exact string written here.
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

	// Only write the plist — do NOT load it with launchctl.
	// launchctl load would start a second instance immediately, causing
	// duplicate tray icons. The plist has RunAtLoad=true, so macOS will
	// auto-start the app on next login.
	return nil
}

func disableAutoStart() error {
	plistPath, err := launchAgentPath()
	if err != nil {
		return fmt.Errorf("resolve plist path: %w", err)
	}

	// Unload the job from the current session.
	unloadCmd := exec.Command("launchctl", "unload", plistPath)
	if out, err := unloadCmd.CombinedOutput(); err != nil {
		// It's OK if the job isn't currently loaded.
		_ = string(out)
	}

	// Remove the plist file.
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

	// Check that the plist references the current executable path.
	exePath, err := util.ExecutablePath()
	if err != nil {
		return false
	}

	return strings.Contains(string(data), exePath)
}
