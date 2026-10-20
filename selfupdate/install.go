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
	// 删除失败多半是上一个进程仍持有文件（Windows）或杀软在扫描，等待时间每轮翻倍。
	cleanupRetryDelay = 3 * time.Second
	cleanupRetries    = 5
)

// resolvedExe 返回符号链接已解析的可执行文件路径。
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

// installTargetDir 返回安装产物的目录：macOS 上是 .app bundle 的父目录，否则是可执行文件所在目录。
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

// appBundleRoot 返回包含 exePath 的 .app 目录，不在 macOS bundle 内时返回空。
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

// installFor 把 stagingDir 中暂存的产物移动到产品的安装位置。
// Windows 不能覆盖正在运行的二进制，只能先重命名到一旁等下次启动删除；unix 靠 rename 原子替换。
func installFor(stagingDir string, product Product) error {
	exe, err := resolvedExe()
	if err != nil {
		return err
	}
	return installAt(exe, stagingDir, product)
}

// permissionHint 把权限错误改写成用户能看懂的提示，原始原因通常指向不清的空间。
func permissionHint(action string, err error) error {
	if os.IsPermission(err) {
		return fmt.Errorf("%s: 安装目录无写权限，请以管理员身份运行后重试", action)
	}
	return fmt.Errorf("%s: %w", action, err)
}

// clearQuarantine 移除新 bundle 上的 macOS 隔离属性，否则 Gatekeeper 会在首次启动时拦截它。
// 尽力而为，失败只记日志。
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

// installBundle 用暂存的 bundle 替换包含当前运行进程的 .app。
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

// CleanupOld 清理自更新遗留的 .old 与暂存目录，尽力而为，失败只记日志。
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
		// 上一个进程可能仍持有句柄（Windows），只能退避重试到它退出。
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
