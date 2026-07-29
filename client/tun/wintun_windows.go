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

	if err := os.WriteFile(target, assets.WintunDLL, 0o444); err != nil {
		return err
	}

	log.Info("[TUN] extracted wintun.dll", "path", target)
	return nil
}
