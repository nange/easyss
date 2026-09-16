package util

import (
	"os"
	"path/filepath"
)

// ExecutablePath returns the real path of the current executable, resolving
// symlinks so the result is stable across launches (macOS Finder/launchd
// launch through a symlinked bundle path). Falls back to the raw
// os.Executable result when symlinks cannot be resolved.
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
