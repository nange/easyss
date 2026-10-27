//go:build windows && !headless

package app

import (
	"fmt"
	"path/filepath"

	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/cmd/easyss/internal/tunhelper"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

// tunUpAuto 返回 Windows 的启用路径：已提权时直接在本进程创建 TUN，普通权限时拉起
// 提权 helper。登录自启动走的是普通权限，因此 TUN 不会在登录时静默安装。
func (s *session) tunUpAuto() error {
	if tunhelper.IsRoot() {
		return s.tunUp()
	}
	return s.tunUpViaHelper()
}

// tunUpViaHelper 通过 ShellExecuteEx("runas") 启动常驻 helper，由 helper 创建 wintun
// 适配器并运行 tun2socks；主进程只持有控制连接，不再需要设备句柄。
func (s *session) tunUpViaHelper() error {
	// 与 session.tunUp、session.tunDown 共用 tunMu。
	s.tunMu.Lock()
	defer s.tunMu.Unlock()

	core := s.currentCore()
	cfg := s.app.currentConfig()

	log.Info("[SYSTRAY] tunUpViaHelper called",
		"tunMgrNil", s.tunMgr == nil,
		"tunRemote", s.tunRemote,
		"coreNil", core == nil)

	if s.tunMgr != nil || s.tunRemote {
		log.Warn("[SYSTRAY] tun session already active, skipping create")
		return nil
	}
	if core == nil || core.Client == nil {
		return fmt.Errorf("client not initialized")
	}
	if core.HTTPServer == nil {
		return fmt.Errorf("http proxy server not started")
	}

	// 用临时 manager 构建设备快照；配置来自与直连路径共享的 builder。
	devCfg := tun.New(s.tunConfig()).DeviceConfig()

	ok, began := false, false
	defer func() {
		if ok {
			return
		}
		core.HTTPServer.ClearTunConfig()
		if began {
			s.cancelRemoteTun()
		}
	}()

	// 必须先预解析服务端域名：helper 会把适配器 DNS 指向本次实测可达的解析器，而解析该
	// 域名又依赖隧道本身，顺序反了会形成解析递归。
	if err := preResolveHelperServer(core, cfg); err != nil {
		return err
	}
	core.HTTPServer.SetTunConfig(newHelperTunConfig(cfg, devCfg))

	// 必须在 spawn 之前发布：helper 的 Start 会在返回 READY 前装好分流路由，直连拨号器
	// 要提前绑定物理接口，避免这段窗口里的直连流量被送进 TUN。
	s.beginRemoteTun(devCfg)
	began = true

	logFile := cfg.Log.FilePath
	if logFile != "" {
		if abs, err := filepath.Abs(logFile); err == nil {
			logFile = abs
		}
	}

	httpAddr := util.LocalProxyDialAddr(cfg.Local.BindAll, cfg.Local.HTTPPort)
	helper, err := tunhelper.Spawn(httpAddr, cfg.TimeoutDuration(), logFile, cfg.Log.Level)
	if err != nil {
		return fmt.Errorf("spawn tun helper: %w", err)
	}

	s.adoptRemoteTun(helper)
	ok = true
	return nil
}
