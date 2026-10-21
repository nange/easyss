//go:build windows

package tun

import (
	"os"
	"path/filepath"

	"github.com/nange/easyss/v3/assets"
	"github.com/nange/easyss/v3/log"
)

func ensureWintun() error {
	if len(assets.WintunDLL) == 0 {
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	target := filepath.Join(dir, "wintun.dll")

	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		return nil
	}

	return writeWintun(target)
}

// 并发首次解压时胜者写成 0444，败者的写入会失败；复核到完整文件即视为成功。
func writeWintun(target string) error {
	if err := os.WriteFile(target, assets.WintunDLL, 0o444); err != nil {
		if info, statErr := os.Stat(target); statErr == nil && !info.IsDir() &&
			info.Size() == int64(len(assets.WintunDLL)) {
			return nil
		}
		return err
	}

	log.Info("[TUN] extracted wintun.dll", "path", target)
	return nil
}
