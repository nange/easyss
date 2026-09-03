package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nange/easyss/v3/log"
)

const stagingPrefix = ".easyss-update-"

const (
	// cleanupRetryDelay is how long CleanupOld waits before the first retry
	// of a deletion that failed because the previous process still held the
	// file (Windows) or antivirus was scanning the freshly renamed binary.
	// The delay doubles after every round, covering roughly a 90-second
	// window in total.
	cleanupRetryDelay = 3 * time.Second
	// cleanupRetries bounds the number of retry rounds.
	cleanupRetries = 5
)

// resolvedExe returns the real path of the running executable, symlinks resolved.
func resolvedExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return exe, nil
}

// installTargetDir returns the directory that hosts the install artifact:
// the parent of the .app bundle on macOS, otherwise the executable directory.
func installTargetDir() (string, error) {
	exe, err := resolvedExe()
	if err != nil {
		return "", err
	}
	if bundle := appBundleRoot(exe); bundle != "" {
		return filepath.Dir(bundle), nil
	}
	return filepath.Dir(exe), nil
}

// appBundleRoot returns the .app bundle directory containing exePath, or an
// empty string when the executable is not inside a macOS bundle.
func appBundleRoot(exePath string) string {
	dir := filepath.Dir(exePath)
	if filepath.Base(dir) != "MacOS" {
		return ""
	}
	contents := filepath.Dir(dir)
	if filepath.Base(contents) != "Contents" {
		return ""
	}
	bundle := filepath.Dir(contents)
	if !strings.HasSuffix(bundle, ".app") {
		return ""
	}
	return bundle
}

// Install moves the artifact staged in stagingDir over the current install
// location. Windows cannot overwrite a running executable, so the running
// binary is renamed aside (allowed) and removed on next start; unix replaces
// the file atomically via rename; macOS swaps the whole .app bundle.
func Install(stagingDir string) error {
	exe, err := resolvedExe()
	if err != nil {
		return err
	}
	return installAt(exe, stagingDir)
}

// permissionHint rewrites a permission failure into a user-friendly message,
// since the reason is otherwise opaque (e.g. Program Files on Windows or
// /Applications on macOS).
func permissionHint(action string, err error) error {
	if os.IsPermission(err) {
		return fmt.Errorf("%s: 安装目录无写权限，请以管理员身份运行后重试", action)
	}
	return fmt.Errorf("%s: %w", action, err)
}

// clearQuarantine removes the macOS quarantine attribute from a freshly
// installed app bundle so Gatekeeper does not block it on first launch. It
// matches the README's manual `xattr -cr` step. Best-effort: a failure is
// logged and does not fail the install.
func clearQuarantine(path string) {
	if runtime.GOOS != "darwin" {
		return
	}
	if err := exec.Command("xattr", "-cr", path).Run(); err != nil {
		log.Warn("[UPDATE] clear quarantine attribute", "path", path, "err", err)
	}
}

func installAt(exe, stagingDir string) error {
	if bundle := appBundleRoot(exe); bundle != "" {
		return installBundle(stagingDir, bundle)
	}

	staged, err := stagedBinary(stagingDir)
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			return permissionHint("rename running executable aside", err)
		}
		if err := os.Rename(staged, exe); err != nil {
			_ = os.Rename(old, exe) // rollback
			return permissionHint("move new executable into place", err)
		}
		return nil
	}

	// unix: atomic replace over the running binary is allowed.
	if err := os.Chmod(staged, 0o755); err != nil { //nolint:gosec // the client binary must stay executable
		return fmt.Errorf("chmod new executable: %w", err)
	}
	if err := os.Rename(staged, exe); err != nil {
		return permissionHint("replace executable", err)
	}
	return nil
}

// stagedBinary locates the client binary extracted into stagingDir.
func stagedBinary(stagingDir string) (string, error) {
	name := "easyss"
	if runtime.GOOS == "windows" {
		name = "easyss.exe"
	}
	p := filepath.Join(stagingDir, name)
	info, err := os.Stat(p)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("staged binary %s not found", p)
	}
	return p, nil
}

// installBundle swaps the .app bundle containing the running process with
// the bundle staged from the release zip.
func installBundle(stagingDir, bundle string) error {
	staged, err := stagedBundle(stagingDir)
	if err != nil {
		return err
	}

	old := bundle + ".old"
	_ = os.RemoveAll(old)
	if err := os.Rename(bundle, old); err != nil {
		return permissionHint("move running bundle aside", err)
	}
	if err := os.Rename(staged, bundle); err != nil {
		_ = os.Rename(old, bundle) // rollback
		return permissionHint("move new bundle into place", err)
	}
	clearQuarantine(bundle)
	return nil
}

// stagedBundle locates the .app directory extracted into stagingDir.
func stagedBundle(stagingDir string) (string, error) {
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return "", fmt.Errorf("read staging dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), ".app") {
			return filepath.Join(stagingDir, e.Name()), nil
		}
	}
	return "", errors.New("no .app bundle found in release zip")
}

// CleanupOld removes leftovers from a previous self-update: the renamed
// running binary/bundle kept for Windows/macOS, and any staging directory a
// crashed update may have left behind. It is best-effort and silent on error.
func CleanupOld() {
	exe, err := resolvedExe()
	if err != nil {
		return
	}
	dirs := []string{filepath.Dir(exe)}
	if bundle := appBundleRoot(exe); bundle != "" {
		dirs = append(dirs, filepath.Dir(bundle))
	}

	var retry []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			isStaging := strings.HasPrefix(name, stagingPrefix)
			isOld := name == filepath.Base(exe)+".old" || strings.HasSuffix(name, ".app.old")
			if !isStaging && !isOld {
				continue
			}
			path := filepath.Join(dir, name)
			if err := os.RemoveAll(path); err != nil {
				log.Warn("[UPDATE] cleanup old artifact", "path", filepath.Base(path), "err", err)
				retry = append(retry, path)
			} else {
				log.Info("[UPDATE] removed leftover from previous update", "path", filepath.Base(path))
			}
		}
	}
	if len(retry) > 0 {
		// The previous process may still hold a handle on the renamed
		// binary/bundle (Windows), so retry with backoff until it has exited.
		go func() {
			delay := cleanupRetryDelay
			pending := retry
			for attempt := 0; attempt < cleanupRetries && len(pending) > 0; attempt++ {
				time.Sleep(delay)
				var still []string
				for _, p := range pending {
					if err := os.RemoveAll(p); err != nil {
						log.Warn("[UPDATE] cleanup old artifact (retry)", "path", filepath.Base(p), "err", err)
						still = append(still, p)
					} else {
						log.Info("[UPDATE] removed leftover from previous update", "path", filepath.Base(p))
					}
				}
				pending = still
				delay *= 2
			}
			for _, p := range pending {
				log.Error("[UPDATE] cleanup old artifact failed after retries", "path", filepath.Base(p))
			}
		}()
	}
}
