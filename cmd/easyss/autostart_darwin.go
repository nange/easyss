//go:build darwin && !without_tray

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// executablePathForAutoStart returns the path to use in the LaunchAgent plist.
// If the current binary is inside an .app bundle (e.g., Easyss.app/Contents/MacOS/easyss),
// it uses the bundle path so that macOS treats it as a proper application.
// Otherwise, it falls back to the raw binary path.
func executablePathForAutoStart() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}

	// Resolve symlinks to get the real path.
	realExe, err := filepath.EvalSymlinks(exe)
	if err != nil {
		realExe = exe
	}

	// Check if running from inside an .app bundle.
	// The bundle structure is: Easyss.app/Contents/MacOS/easyss
	macOSDir := filepath.Dir(realExe)      // .../Contents/MacOS
	contentsDir := filepath.Dir(macOSDir)  // .../Contents
	appBundle := filepath.Dir(contentsDir) // .../Easyss.app

	if strings.HasSuffix(macOSDir, "/MacOS") && strings.HasSuffix(contentsDir, "/Contents") && strings.HasSuffix(appBundle, ".app") {
		// Running from inside a proper .app bundle, use the bundle path.
		return realExe, nil
	}

	return realExe, nil
}

func enableAutoStart() error {
	exePath, err := executablePathForAutoStart()
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

	// Bootstrap so the job is active for the current session immediately.
	uid := os.Getuid()
	bootstrapCmd := exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", uid), plistPath)
	if out, err := bootstrapCmd.CombinedOutput(); err != nil {
		// launchctl may fail if the binary has not been cleared by Gatekeeper yet,
		// but the plist is written and will be picked up on next login.
		return fmt.Errorf("launchctl bootstrap: %w (output: %s)", err, string(out))
	}

	return nil
}

func disableAutoStart() error {
	plistPath, err := launchAgentPath()
	if err != nil {
		return fmt.Errorf("resolve plist path: %w", err)
	}

	// Bootout the job from the current session.
	uid := os.Getuid()
	bootoutCmd := exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/com.github.nange.easyss", uid))
	if out, err := bootoutCmd.CombinedOutput(); err != nil {
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
	exePath, err := executablePathForAutoStart()
	if err != nil {
		return false
	}

	return strings.Contains(string(data), exePath)
}
