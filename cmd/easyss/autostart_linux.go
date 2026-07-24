//go:build linux && !without_tray

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	autoStartDir     = ".config/autostart"
	autoStartDesktop = "easyss.desktop"
)

func autoStartDesktopPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, autoStartDir, autoStartDesktop), nil
}

func enableAutoStart() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}

	desktopPath, err := autoStartDesktopPath()
	if err != nil {
		return fmt.Errorf("resolve desktop path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(desktopPath), 0755); err != nil {
		return fmt.Errorf("mkdir autostart dir: %w", err)
	}

	content := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=Easyss
Exec=%s
X-GNOME-Autostart-enabled=true
Terminal=false
`, exe)

	if err := os.WriteFile(desktopPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write desktop file: %w", err)
	}

	return nil
}

func disableAutoStart() error {
	desktopPath, err := autoStartDesktopPath()
	if err != nil {
		return fmt.Errorf("resolve desktop path: %w", err)
	}

	if err := os.Remove(desktopPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove desktop file: %w", err)
	}

	return nil
}

func isAutoStartEnabled() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}

	desktopPath, err := autoStartDesktopPath()
	if err != nil {
		return false
	}

	data, err := os.ReadFile(desktopPath)
	if err != nil {
		return false
	}

	expectedLine := fmt.Sprintf("Exec=%s\n", exe)
	for _, line := range splitLines(string(data)) {
		if line == expectedLine {
			return true
		}
	}

	return false
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
