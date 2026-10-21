package main

import (
	"errors"
	"fmt"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"github.com/wzshiming/sysproxy"
)

// sysProxyAddr 返回系统代理与会话环境应指向的本地 HTTP 入口地址，与入口的监听地址
// 同源（见 util.LocalProxyDialAddr）：bind_all 时入口监听 [::]，这里必须给同族回环
// [::1]，写死 127.0.0.1 会让系统代理指向一个连不上的入口。
func sysProxyAddr(cfg *clientconfig.ClientConfig) string {
	return util.LocalProxyDialAddr(cfg.Local.BindAll, cfg.Local.HTTPPort)
}

// setSysProxy 通过桌面代理设置（gsettings/kioslaverc/注册表/networksetup）与 Linux 的
// 会话环境两种机制指向本地 HTTP 代理——Chromium 在无法识别的桌面（含 Hyprland）上忽略
// gsettings。任一机制生效即返回 nil，调用方可以依赖 unsetSysProxy 再次撤销它。
func setSysProxy(env *proxyEnvState, addr string) error {
	settingsErr := errors.Join(
		wrapProxyErr("set http proxy", sysproxy.OnHTTP(addr)),
		wrapProxyErr("set https proxy", sysproxy.OnHTTPS(addr)),
	)
	envApplied, envErr := env.set(addr)

	if settingsErr != nil && !envApplied {
		return errors.Join(settingsErr, envErr)
	}
	if settingsErr != nil {
		log.Warn("[SYSPROXY] desktop proxy settings not updated, relying on the session environment", "err", settingsErr)
	}
	if envErr != nil {
		log.Warn("[SYSPROXY] session environment not updated", "err", envErr)
	}

	log.Info("[SYSPROXY] proxy enabled", "addr", addr)
	return nil
}

func unsetSysProxy(env *proxyEnvState) error {
	settingsErr := errors.Join(
		wrapProxyErr("unset http proxy", sysproxy.OffHTTP()),
		wrapProxyErr("unset https proxy", sysproxy.OffHTTPS()),
	)
	envApplied, envErr := env.unset()

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

// wrapProxyErr 给错误加上标签，但不会把 nil 错误变成非 nil，这样每一步都成功时
// errors.Join 仍会报告成功。
func wrapProxyErr(msg string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", msg, err)
}
