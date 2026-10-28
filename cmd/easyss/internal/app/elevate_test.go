//go:build !headless

package app

import (
	"testing"

	"github.com/gogpu/systray"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/cmd/easyss/internal/tray"
	"github.com/stretchr/testify/require"
)

// newElevationTestApp 构建只带"代理对象"菜单的最小 trayApp：提权分支只用到配置快照、
// 菜单勾选与注入的 requestElevation，不需要托盘、核心或网络。系统代理改注入实现：
// 授权成功后本进程会走 exitApp 收尾，绝不能碰测试机上的真实代理设置。
func newElevationTestApp(t *testing.T, request func(*App) error) *trayApp {
	t.Helper()

	cfg := &clientconfig.ClientConfig{}
	a := &trayApp{App: New(cfg, "config.json"), shell: tray.NewShell()}
	a.ui = a
	a.object = tray.NewObjectMenu(systray.NewMenu(), cfg, func() {}, func() {})
	a.deps.requestElevation = request
	a.deps.isElevated = func() bool { return false }
	a.deps.sysProxyApply = func(string) error { return nil }
	a.deps.sysProxyRevert = func() error { return nil }
	return a
}

// TestRequestTunElevationLeavesTheRequestInPlaceWhenUnsupported 固定 darwin/linux 的分支：
// 那里由 tunUpAuto 用 pkexec/osascript 原地提权，勾选不能在这里被清掉——否则授权成功后
// 菜单仍显示未开启。
func TestRequestTunElevationLeavesTheRequestInPlaceWhenUnsupported(t *testing.T) {
	requested := false
	a := newElevationTestApp(t, func(*App) error {
		requested = true
		return errElevationUnsupported
	})
	a.object.SetTunChecked(true)

	require.False(t, a.requestTunElevation(), "不支持的平台必须交回调用方处理")
	require.True(t, requested)
	require.True(t, a.object.TunChecked(), "原地提权路径不得改动勾选")
}

// TestRequestTunElevationRevertsTheCheckWhenCancelled 守住取消授权后的界面：本进程不会再
// 装 TUN，勾选留着就变成"菜单说已开启、系统毫无改动"。
func TestRequestTunElevationRevertsTheCheckWhenCancelled(t *testing.T) {
	a := newElevationTestApp(t, func(*App) error { return errElevationCancelled })
	a.object.SetTunChecked(true)

	require.True(t, a.requestTunElevation(), "取消授权也算已接管本次点击")
	require.False(t, a.object.TunChecked())
}

// TestRequestTunElevationHandsOverTheConfigFile 固定接管参数：新实例必须读同一份配置，
// 否则会以默认服务器/端口启动，用户看到的是"重启后配置全丢了"。
func TestRequestTunElevationHandsOverTheConfigFile(t *testing.T) {
	var got string
	a := newElevationTestApp(t, func(app *App) error {
		got = app.configFile
		return nil
	})
	a.object.SetTunChecked(true)

	require.True(t, a.requestTunElevation())
	require.Equal(t, "config.json", got)
	require.False(t, a.object.TunChecked(), "接管后本进程不再声称 TUN 已开启")
}

// TestEnableTunAsksForElevationBeforeTouchingTheDevice 守住点击链路的顺序：普通权限下先请求
// 提权并返回，不能落到本进程的建 TUN 路径（那一步在 asInvoker 构建里必然失败）。
func TestEnableTunAsksForElevationBeforeTouchingTheDevice(t *testing.T) {
	requests := 0
	a := newElevationTestApp(t, func(*App) error {
		requests++
		return nil
	})

	a.enableTun2socks()

	require.Equal(t, 1, requests)
	a.sess.tunMu.Lock()
	defer a.sess.tunMu.Unlock()
	require.Nil(t, a.sess.tunMgr, "提权请求之后不得在本进程建立 TUN 会话")
}

// TestEnableTunStaysInProcessWhenElevated 确认已提权进程原地建 TUN（不重启），
// 这条路径的失败只来自"核心未初始化"，不能变成又一次提权请求。
func TestEnableTunStaysInProcessWhenElevated(t *testing.T) {
	requests := 0
	a := newElevationTestApp(t, func(*App) error {
		requests++
		return nil
	})
	a.deps.isElevated = func() bool { return true }

	a.enableTun2socks()

	require.Zero(t, requests, "已提权时不得重启进程")
}
