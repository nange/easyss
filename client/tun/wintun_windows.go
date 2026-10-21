//go:build windows

package tun

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/nange/easyss/v3/assets"
	"github.com/nange/easyss/v3/log"
)

// 进程内并发解压由它串行化；测试会并行调用 ensureWintunAt。
var wintunMu sync.Mutex

func ensureWintun() error {
	if len(assets.WintunDLL) == 0 {
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return ensureWintunAt(filepath.Join(filepath.Dir(exe), "wintun.dll"))
}

// ensureWintunAt 把 DLL 解压到 target。进程内由 wintunMu 串行化，跨进程靠
// "完整文件已存在即成功"兜底。
func ensureWintunAt(target string) error {
	wintunMu.Lock()
	defer wintunMu.Unlock()

	if wintunReady(target) {
		return nil
	}

	// 旧版本或上次中断留下的只读文件必须先恢复可写，否则覆盖会失败。
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		if err := os.Chmod(target, 0o644); err != nil {
			return err
		}
	}

	if err := os.WriteFile(target, assets.WintunDLL, 0o444); err != nil {
		if wintunReady(target) {
			return nil
		}
		return err
	}

	log.Info("[TUN] extracted wintun.dll", "path", target)
	return nil
}

func wintunReady(target string) bool {
	info, err := os.Stat(target)
	return err == nil && !info.IsDir() && info.Size() == int64(len(assets.WintunDLL))
}
