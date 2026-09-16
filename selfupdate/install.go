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
	// cleanupRetryDelay 是 CleanupOld 在重试删除前的首次等待时长。删除失败通常
	// 是因为上一个进程仍持有该文件（Windows），或杀毒软件正在扫描刚重命名的
	// 二进制。每轮重试后等待时间翻倍，总共覆盖约 90 秒的时间窗口。
	cleanupRetryDelay = 3 * time.Second
	// cleanupRetries 限制重试轮数。
	cleanupRetries = 5
)

// resolvedExe 返回正在运行的可执行文件的真实路径（符号链接已解析）。
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

// installTargetDir 返回承载安装产物的目录：在 macOS 上是 .app bundle 的
// 父目录，否则是可执行文件所在目录。
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

// appBundleRoot 返回包含 exePath 的 .app bundle 目录；当可执行文件不在
// macOS bundle 内时返回空字符串。
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

// installFor 将 stagingDir 中暂存的产物移动到给定产品的安装位置。
// Windows 无法覆盖正在运行的可执行文件，因此先把运行中的二进制重命名到一旁
// （允许这样做），并在下次启动时删除；unix 通过 rename 原子替换文件；
// macOS 则整体替换 .app bundle。
func installFor(stagingDir string, product Product) error {
	exe, err := resolvedExe()
	if err != nil {
		return err
	}
	return installAt(exe, stagingDir, product)
}

// permissionHint 将权限错误改写为对用户友好的提示信息，因为原始错误原因
// 通常不直观（例如 Windows 的 Program Files 或 macOS 的 /Applications）。
func permissionHint(action string, err error) error {
	if os.IsPermission(err) {
		return fmt.Errorf("%s: 安装目录无写权限，请以管理员身份运行后重试", action)
	}
	return fmt.Errorf("%s: %w", action, err)
}

// clearQuarantine 移除新安装的 app bundle 上的 macOS 隔离属性，避免
// Gatekeeper 在首次启动时拦截它。这与 README 中手动执行 `xattr -cr` 的步骤
// 一致。尽力而为：失败仅记录日志，不会导致安装失败。
func clearQuarantine(path string) {
	if runtime.GOOS != "darwin" {
		return
	}
	if err := exec.Command("xattr", "-cr", path).Run(); err != nil {
		log.Warn("[UPDATE] clear quarantine attribute", "path", path, "err", err)
	}
}

func installAt(exe, stagingDir string, product Product) error {
	if bundle := appBundleRoot(exe); bundle != "" {
		return installBundle(stagingDir, bundle)
	}

	staged, err := stagedBinary(stagingDir, product)
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
			_ = os.Rename(old, exe) // 回滚
			return permissionHint("move new executable into place", err)
		}
		return nil
	}

	// unix：允许对运行中的二进制进行原子替换。
	if err := os.Chmod(staged, 0o755); err != nil { //nolint:gosec // 客户端二进制必须保持可执行
		return fmt.Errorf("chmod new executable: %w", err)
	}
	if err := os.Rename(staged, exe); err != nil {
		return permissionHint("replace executable", err)
	}
	return nil
}

// stagedBinary 定位解压到 stagingDir 中的产品二进制。
func stagedBinary(stagingDir string, product Product) (string, error) {
	p := filepath.Join(stagingDir, product.binaryName())
	info, err := os.Stat(p)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("staged binary %s not found", p)
	}
	return p, nil
}

// installBundle 用从 release zip 中暂存的 bundle 替换包含当前运行进程的
// .app bundle。
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
		_ = os.Rename(old, bundle) // 回滚
		return permissionHint("move new bundle into place", err)
	}
	clearQuarantine(bundle)
	return nil
}

// stagedBundle 定位解压到 stagingDir 中的 .app 目录。
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

// CleanupOld 清理上次自更新遗留的文件：为 Windows/macOS 保留的重命名后的
// 运行中二进制/bundle，以及崩溃的更新可能遗留的暂存目录。它是尽力而为的，
// 出错时不会向调用方返回错误（仅记录日志）。
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
		// 上一个进程可能仍持有重命名后的二进制/bundle 的句柄（Windows），
		// 因此按退避策略重试，直到它退出。
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
