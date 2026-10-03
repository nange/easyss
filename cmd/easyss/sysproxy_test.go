package main

import (
	"errors"
	"slices"
	"testing"

	clientconfig "github.com/nange/easyss/v3/client/config"
)

// stubSysProxy 替换系统代理的设置/撤销钩子，记录被设置的端口与撤销次数，
// 使测试不必触碰运行测试的机器的真实系统代理配置。
func stubSysProxy(t *testing.T, applyErr error) (applied *[]int, reverts *int) {
	t.Helper()

	prevApply, prevRevert := sysProxyApply, sysProxyRevert
	t.Cleanup(func() {
		sysProxyApply, sysProxyRevert = prevApply, prevRevert
	})

	applied = &[]int{}
	reverts = new(int)
	sysProxyApply = func(port int) error {
		*applied = append(*applied, port)
		return applyErr
	}
	sysProxyRevert = func() error {
		*reverts++
		return nil
	}
	return applied, reverts
}

func testApp(local clientconfig.LocalConfig) *App {
	return newApp(&clientconfig.ClientConfig{Local: local}, "")
}

func TestSetupSysProxyAppliesLocalHTTPPort(t *testing.T) {
	applied, _ := stubSysProxy(t, nil)

	app := testApp(clientconfig.LocalConfig{HTTPPort: 5080})
	if !app.setupSysProxy() {
		t.Fatal("setupSysProxy = false, want true")
	}
	if want := []int{5080}; !slices.Equal(*applied, want) {
		t.Fatalf("applied ports = %v, want %v", *applied, want)
	}
}

func TestSetupSysProxyHonorsDisableSwitch(t *testing.T) {
	applied, _ := stubSysProxy(t, nil)

	app := testApp(clientconfig.LocalConfig{HTTPPort: 5080, DisableSysProxy: true})
	if app.setupSysProxy() {
		t.Fatal("setupSysProxy = true, want false when disable_sys_proxy is set")
	}
	if len(*applied) != 0 {
		t.Fatalf("applied ports = %v, want none", *applied)
	}
}

func TestSetupSysProxySkipsInvalidHTTPPort(t *testing.T) {
	applied, _ := stubSysProxy(t, nil)

	app := testApp(clientconfig.LocalConfig{HTTPPort: 0})
	if app.setupSysProxy() {
		t.Fatal("setupSysProxy = true, want false without a local HTTP port")
	}
	if len(*applied) != 0 {
		t.Fatalf("applied ports = %v, want none", *applied)
	}
}

// setupSysProxy 失败只记警告并返回 false：调用方据此不撤销，
// 启动流程本身不会失败。
func TestSetupSysProxyFailureIsNotFatal(t *testing.T) {
	applied, _ := stubSysProxy(t, errors.New("gsettings: command not found"))

	app := testApp(clientconfig.LocalConfig{HTTPPort: 5080})
	if app.setupSysProxy() {
		t.Fatal("setupSysProxy = true, want false when applying fails")
	}
	if len(*applied) != 1 {
		t.Fatalf("apply called %d times, want 1", len(*applied))
	}
}

func TestTeardownSysProxyOnlyRevertsWhenApplied(t *testing.T) {
	_, reverts := stubSysProxy(t, nil)

	teardownSysProxy(false)
	if *reverts != 0 {
		t.Fatalf("reverts = %d, want 0 without a preceding apply", *reverts)
	}

	teardownSysProxy(true)
	if *reverts != 1 {
		t.Fatalf("reverts = %d, want 1", *reverts)
	}
}
