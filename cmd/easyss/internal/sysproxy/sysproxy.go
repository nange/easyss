package sysproxy

import (
	"errors"
	"fmt"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	wsysproxy "github.com/wzshiming/sysproxy"
)

// Addr 返回系统代理与会话环境应指向的本地 HTTP 入口地址，与入口的监听地址
// 同源（见 util.LocalProxyDialAddr）：bind_all 时入口监听 [::]，这里必须给同族回环
// [::1]，写死 127.0.0.1 会让系统代理指向一个连不上的入口。
func Addr(cfg *clientconfig.ClientConfig) string {
	return util.LocalProxyDialAddr(cfg.Local.BindAll, cfg.Local.HTTPPort)
}

// ErrResidual 表示设置系统代理时只有部分协议写入成功、补偿撤销也失败：系统代理可能
// 仍指向本地入口。调用方必须把它当作"已改动系统代理"，在退出时再撤销一次。
var ErrResidual = errors.New("system proxy may still point to the local entry")

// desktopProxy 是系统级代理设置的读写入口；测试替换它，避免改动运行测试的机器的真实
// 系统代理设置。
type desktopProxy struct {
	onHTTP   func(addr string) error
	onHTTPS  func(addr string) error
	offHTTP  func() error
	offHTTPS func() error
}

// New 返回平台实现的会话环境状态。
func New() *State {
	return &State{desktop: desktopProxy{
		onHTTP:   wsysproxy.OnHTTP,
		onHTTPS:  wsysproxy.OnHTTPS,
		offHTTP:  wsysproxy.OffHTTP,
		offHTTPS: wsysproxy.OffHTTPS,
	}}
}

// Enable 通过桌面代理设置（gsettings/kioslaverc/注册表/networksetup）与 Linux 的
// 会话环境两种机制指向本地 HTTP 代理——Chromium 在无法识别的桌面（含 Hyprland）上忽略
// gsettings。任一机制生效即返回 nil，调用方可以依赖 Disable 再次撤销它。
func (s *State) Enable(addr string) error {
	httpErr := wrapProxyErr("set http proxy", s.desktop.onHTTP(addr))
	httpsErr := wrapProxyErr("set https proxy", s.desktop.onHTTPS(addr))
	settingsErr := errors.Join(httpErr, httpsErr)
	envApplied, envErr := s.set(addr)

	if settingsErr != nil && !envApplied {
		// http/https 是两次独立读改写：只有一边成功会留下退出时不会被撤销的代理，先自行撤销。
		if httpErr == nil || httpsErr == nil {
			if revertErr := s.revertSettings(); revertErr != nil {
				return fmt.Errorf("%w: %w", ErrResidual, errors.Join(settingsErr, envErr, revertErr))
			}
		}
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

func (s *State) Disable() error {
	settingsErr := s.revertSettings()
	envApplied, envErr := s.unset()

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

// revertSettings 撤销桌面代理设置；Enable 的部分写入补偿与 Disable 共用它。
func (s *State) revertSettings() error {
	return errors.Join(
		wrapProxyErr("unset http proxy", s.desktop.offHTTP()),
		wrapProxyErr("unset https proxy", s.desktop.offHTTPS()),
	)
}

// wrapProxyErr 给错误加上标签，但不会把 nil 错误变成非 nil，这样每一步都成功时
// errors.Join 仍会报告成功。
func wrapProxyErr(msg string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", msg, err)
}
