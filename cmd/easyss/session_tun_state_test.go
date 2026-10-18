//go:build !headless && (darwin || linux)

package main

import (
	"testing"

	"github.com/nange/easyss/v3/client/config"
)

// TestNonRootTunStartClearsPreference 固定“跳过 TUN 必须落状态”：非 root 启动
// 无法直接创建设备，若只提示而不清 EnableTun2socks，托盘会按 currentConfig
// 勾选“系统全局流量”，实际却没有 tunMgr；第一次点击还会走关闭分支。
func TestNonRootTunStartClearsPreference(t *testing.T) {
	if IsRoot() {
		t.Skip("running as root: the non-root TUN branch is not taken")
	}

	stubRunCore(t)
	a := newApp(&config.ClientConfig{}, "")
	a.updateConfig(func(c *config.ClientConfig) { c.Local.EnableTun2socks = true })

	if err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(a.Stop)

	if got := a.currentConfig().Local.EnableTun2socks; got {
		t.Fatal("EnableTun2socks must be cleared when TUN is skipped for lack of root")
	}
}
