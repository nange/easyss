//go:build !headless && windows

package app

import (
	"testing"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/stretchr/testify/require"
)

// proxyOnUI 只覆盖 stubAppUI 里提权路径用到的那个方法：其余界面回调不会在本用例里触发。
type proxyOnUI struct{ *stubAppUI }

func (proxyOnUI) browserProxyEnabled() bool { return true }

// TestRestartArgsCarriesTheRuntimeState 固定提权重启的命令行：载荷必须用等号形式带在
// -elevated-restart 上（空格形式会被 flag 当成位置参数丢掉），配置路径的引号交给
// ComposeCommandLine，路径带空格时不会被拆成多个参数。
func TestRestartArgsCarriesTheRuntimeState(t *testing.T) {
	st := RestartState{
		enabled:     true,
		serverIndex: 2,
		sysProxy:    "off",
		proxyRule:   "proxy",
		logLevel:    "debug",
	}
	require.Equal(t,
		"-elevated-restart=server=2,sysproxy=off,rule=proxy,log=debug -enable-tun2socks",
		restartArgs("", st))
	require.Equal(t,
		`-elevated-restart=server=2,sysproxy=off,rule=proxy,log=debug -enable-tun2socks -c "C:\Users\some one\Easyss\config.json"`,
		restartArgs(`C:\Users\some one\Easyss\config.json`, st),
		"配置路径必须整体加引号")
}

// TestNewRestartStateSnapshotsTheRuntimeSelections 固定交接内容：服务器下标、浏览器代理
// 开关、规则与日志级别都来自旧实例的当前快照/菜单，而不是配置文件。
func TestNewRestartStateSnapshotsTheRuntimeSelections(t *testing.T) {
	cfg := &clientconfig.ClientConfig{Servers: []*clientconfig.ServerProfile{{Host: "a"}, {Host: "b"}}}
	cfg.SetDefaultServerIndex(1)
	cfg.Routing.ProxyRule = "direct"
	cfg.Log.Level = "warn"
	cfg.Local.DisableSysProxy = true

	a := New(cfg, "config.json")
	a.ui = proxyOnUI{newStubAppUI()}

	require.Equal(t, RestartState{
		enabled:     true,
		serverIndex: 1,
		sysProxy:    "on",
		proxyRule:   "direct",
		logLevel:    "warn",
	}, newRestartState(a), "重启后的选择必须来自内存快照与菜单，不是配置文件")
}
