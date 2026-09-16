package main

import (
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/tun"
)

// failedTunManager 构建一个 Start() 会立即失败的 manager，这样无需 root、
// 也无需接触真实的 TUN 设备即可测试引擎失败路径：不可解析的日志级别会被
// 引擎的 general() 步骤拒绝，此时尚未打开任何设备。
func failedTunManager() *tun.Manager {
	return tun.New(tun.Config{LogLevel: "not-a-log-level"})
}

// TestStartTunEngineReportsFailureToHook 固定托盘所依赖的契约：引擎启动失败
// 必须触发 tunStartFailureHook，该钩子会复原菜单项并拆除提权 helper。否则
// 菜单会一直声称 TUN 已开启，而实际上没有任何流量经过它。
func TestStartTunEngineReportsFailureToHook(t *testing.T) {
	orig := tunStartFailureHook
	t.Cleanup(func() { tunStartFailureHook = orig })

	called := make(chan struct{}, 1)
	tunStartFailureHook = func() { called <- struct{}{} }

	startTunEngine(failedTunManager(), "device")

	select {
	case <-called:
	case <-time.After(30 * time.Second):
		t.Fatal("tunStartFailureHook was not called after the engine failed to start")
	}
}
