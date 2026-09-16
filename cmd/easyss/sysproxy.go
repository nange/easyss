//go:build !headless

package main

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/nange/easyss/v3/log"
	"github.com/wzshiming/sysproxy"
)

// setSysProxy 通过两种可用机制把系统指向本地 HTTP 代理：
// 桌面代理设置（GNOME 的 gsettings、KDE 的 kioslaverc、
// Windows 的注册表、macOS 的 networksetup）以及 —— Linux 上 —— 会话环境。
// 后者供不读取桌面设置的程序使用；例如 Chromium 会在所有它无法识别的
// 桌面环境（包括 Hyprland）上忽略 gsettings。
//
// 只要两种机制之一生效，返回的 error 即为 nil，
// 因此调用方可以依赖 unsetSysProxy 再次撤销它。
func setSysProxy(port int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	settingsErr := errors.Join(
		wrapProxyErr("set http proxy", sysproxy.OnHTTP(addr)),
		wrapProxyErr("set https proxy", sysproxy.OnHTTPS(addr)),
	)
	envApplied, envErr := setSysProxyEnv(port)

	if settingsErr != nil && !envApplied {
		return errors.Join(settingsErr, envErr)
	}
	if settingsErr != nil {
		log.Warn("[SYSPROXY] desktop proxy settings not updated, relying on the session environment", "err", settingsErr)
	}
	if envErr != nil {
		log.Warn("[SYSPROXY] session environment not updated", "err", envErr)
	}

	log.Info("[SYSPROXY] proxy enabled", "port", strconv.Itoa(port))
	return nil
}

func unsetSysProxy() error {
	settingsErr := errors.Join(
		wrapProxyErr("unset http proxy", sysproxy.OffHTTP()),
		wrapProxyErr("unset https proxy", sysproxy.OffHTTPS()),
	)
	envApplied, envErr := unsetSysProxyEnv()

	if settingsErr != nil && !envApplied {
		return errors.Join(settingsErr, envErr)
	}
	if settingsErr != nil {
		log.Warn("[SYSPROXY] desktop proxy settings not restored", "err", settingsErr)
	}
	if envErr != nil {
		log.Warn("[SYSPROXY] session environment not restored", "err", envErr)
	}

	log.Info("[SYSPROXY] proxy disabled")
	return nil
}

// wrapProxyErr 给错误加上标签，但不会把 nil 错误变成非 nil，
// 这样当每一步都成功时 errors.Join 仍会报告成功。
func wrapProxyErr(msg string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", msg, err)
}
