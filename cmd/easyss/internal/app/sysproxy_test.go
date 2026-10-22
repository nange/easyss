package app

import (
	"errors"
	"slices"
	"testing"

	clientconfig "github.com/nange/easyss/v3/client/config"
)

// stubSysProxy 替换系统代理的设置/撤销钩子，记录被设置的地址与撤销次数，
// 使测试不必触碰运行测试的机器的真实系统代理配置。
func stubSysProxy(a *App, applyErr error) (applied *[]string, reverts *int) {
	applied = &[]string{}
	reverts = new(int)
	a.deps.sysProxyApply = func(addr string) error {
		*applied = append(*applied, addr)
		return applyErr
	}
	a.deps.sysProxyRevert = func() error {
		*reverts++
		return nil
	}
	return applied, reverts
}

func testApp(local clientconfig.LocalConfig) *App {
	return New(&clientconfig.ClientConfig{Local: local}, "")
}

func TestSetupSysProxyAppliesLocalHTTPAddr(t *testing.T) {
	app := testApp(clientconfig.LocalConfig{HTTPPort: 5080})
	applied, _ := stubSysProxy(app, nil)
	if !app.setupSysProxy() {
		t.Fatal("setupSysProxy = false, want true")
	}
	if want := []string{"127.0.0.1:5080"}; !slices.Equal(*applied, want) {
		t.Fatalf("applied addrs = %v, want %v", *applied, want)
	}
}

// TestSetupSysProxyFollowsBindAll 守护本 issue 的核心失败模式：bind_all 时本地
// HTTP 入口监听 [::]，系统代理必须指向同族回环 [::1]。写死 127.0.0.1 的实现
// 在只接受 IPv6 回环的环境里把系统指向一个连不上的入口（浏览器全部无法上网）。
func TestSetupSysProxyFollowsBindAll(t *testing.T) {
	app := testApp(clientconfig.LocalConfig{HTTPPort: 5080, BindAll: true})
	applied, _ := stubSysProxy(app, nil)
	if !app.setupSysProxy() {
		t.Fatal("setupSysProxy = false, want true")
	}
	if want := []string{"[::1]:5080"}; !slices.Equal(*applied, want) {
		t.Fatalf("applied addrs = %v, want %v", *applied, want)
	}
}

func TestSetupSysProxyHonorsDisableSwitch(t *testing.T) {
	app := testApp(clientconfig.LocalConfig{HTTPPort: 5080, DisableSysProxy: true})
	applied, _ := stubSysProxy(app, nil)
	if app.setupSysProxy() {
		t.Fatal("setupSysProxy = true, want false when disable_sys_proxy is set")
	}
	if len(*applied) != 0 {
		t.Fatalf("applied addrs = %v, want none", *applied)
	}
}

func TestSetupSysProxySkipsInvalidHTTPPort(t *testing.T) {
	app := testApp(clientconfig.LocalConfig{HTTPPort: 0})
	applied, _ := stubSysProxy(app, nil)
	if app.setupSysProxy() {
		t.Fatal("setupSysProxy = true, want false without a local HTTP port")
	}
	if len(*applied) != 0 {
		t.Fatalf("applied addrs = %v, want none", *applied)
	}
}

// setupSysProxy 失败只记警告并返回 false：调用方据此不撤销，
// 启动流程本身不会失败。
func TestSetupSysProxyFailureIsNotFatal(t *testing.T) {
	app := testApp(clientconfig.LocalConfig{HTTPPort: 5080})
	applied, _ := stubSysProxy(app, errors.New("gsettings: command not found"))
	if app.setupSysProxy() {
		t.Fatal("setupSysProxy = true, want false when applying fails")
	}
	if len(*applied) != 1 {
		t.Fatalf("apply called %d times, want 1", len(*applied))
	}
}

func TestTeardownSysProxyOnlyRevertsWhenApplied(t *testing.T) {
	app := testApp(clientconfig.LocalConfig{HTTPPort: 5080})
	_, reverts := stubSysProxy(app, nil)

	app.teardownSysProxy()
	if *reverts != 0 {
		t.Fatalf("reverts = %d, want 0 without a preceding apply", *reverts)
	}

	if !app.setupSysProxy() {
		t.Fatal("setupSysProxy = false, want true")
	}
	app.teardownSysProxy()
	if *reverts != 1 {
		t.Fatalf("reverts = %d, want 1", *reverts)
	}

	// 状态已在第一次撤销时清掉，重复调用不得再次撤别人的系统代理。
	app.teardownSysProxy()
	if *reverts != 1 {
		t.Fatalf("reverts = %d, want 1 after a repeated teardown", *reverts)
	}
}

// TestAppStopRevertsSysProxyAndStopsOnce 固定 App.Stop 成为唯一的退出序列：
// 撤销系统代理与停止会话都只发生一次，headless/托盘/无托盘路径共享它。
func TestAppStopRevertsSysProxyAndStopsOnce(t *testing.T) {
	app := testApp(clientconfig.LocalConfig{HTTPPort: 5080})
	_, reverts := stubSysProxy(app, nil)
	if !app.setupSysProxy() {
		t.Fatal("setupSysProxy = false, want true")
	}

	app.Stop()
	app.Stop()
	if *reverts != 1 {
		t.Fatalf("reverts = %d, want 1 across repeated Stop calls", *reverts)
	}
}

// TestAppCloseRevertsEvenWhenNotApplied 固定 Close 与 Stop 的唯一语义差异：
// 托盘退出必须清理上一次运行/异步开关留下的系统代理，因此即使本进程没有
// 成功 apply 过（flag 为假），Close 仍会执行一次 revert。
func TestAppCloseRevertsEvenWhenNotApplied(t *testing.T) {
	app := testApp(clientconfig.LocalConfig{HTTPPort: 5080})
	_, reverts := stubSysProxy(app, nil)
	if app.sysProxyApplied.Load() {
		t.Fatal("a fresh App must not claim it applied the system proxy")
	}

	app.Close()
	if *reverts != 1 {
		t.Fatalf("reverts = %d, want 1 even without a preceding apply", *reverts)
	}
	if app.sysProxyApplied.Load() {
		t.Fatal("Close must leave sysProxyApplied false")
	}
}
