//go:build !headless

package main

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/nange/easyss/v3/log"
	"github.com/wzshiming/sysproxy"
)

// setSysProxy points the system at the local http proxy through both available
// mechanisms: the desktop proxy settings (gsettings on GNOME, kioslaverc on KDE,
// the registry on Windows, networksetup on macOS) and -- on Linux -- the session
// environment. The latter is what programs that do not read the desktop settings
// use; Chromium, for example, ignores gsettings on every desktop environment it
// does not recognise, which includes Hyprland.
//
// The returned error is nil as soon as one of the two mechanisms took effect,
// so that a caller can rely on unsetSysProxy undoing it again.
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

// wrapProxyErr labels an error without turning a nil error into a non-nil one,
// so that errors.Join keeps reporting success when every step succeeded.
func wrapProxyErr(msg string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", msg, err)
}
