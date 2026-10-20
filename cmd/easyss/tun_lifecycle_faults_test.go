//go:build (darwin || linux) && !headless

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/stretchr/testify/require"
)

// 三条故障注入测试：启动失败后的会话回滚、Stop 与 Start 并发、路由残留。全部通过包级
// 钩子驱动，不需要 root 与 TUN 设备，也不碰测试机的网络。创建脚本中途失败本身由
// client/tun 覆盖（它能替换包内的 createTunDevFn），本文件守的是它对**会话层**的后果。

// TestFaultStartFailureRollsBackTheSession 固定一次启动失败对**会话层**的后果：会话被
// 拆掉、偏好回落、所有权回到默认值、界面收到真实原因。failedTunManager 的 LogLevel
// 非法，Start 在 validateEngineKey 处早退，故全程不需要 root、不碰设备。
func TestFaultStartFailureRollsBackTheSession(t *testing.T) {
	a := newApp(&config.ClientConfig{}, "")
	ui := newStubAppUI()
	a.ui = ui
	var teardownOwners []tun.Owner
	a.sess.verifyTeardown = func(_ tun.DeviceConfig, owner tun.Owner, _ bool) error {
		teardownOwners = append(teardownOwners, owner)
		return nil
	}

	a.updateConfig(func(c *config.ClientConfig) { c.Local.EnableTun2socks = true })

	mgr := failedTunManager()
	a.sess.tunMu.Lock()
	a.sess.tunMgr = mgr
	a.sess.tunSession = &tun.DeviceConfig{Device: "tun-halfway"}
	a.sess.tunOwner = tun.OwnerLocal
	a.sess.tunMu.Unlock()

	errStart := errors.New("tun: create device: exit status 1")
	a.sess.rollbackFailedTunStart(mgr, errStart)

	a.sess.tunMu.Lock()
	remaining, dev, owner := a.sess.tunMgr, a.sess.tunSession, a.sess.tunOwner
	a.sess.tunMu.Unlock()

	require.Nil(t, remaining, "半途失败的会话必须被拆掉，否则下次启用会命中'已设置'保护")
	require.Nil(t, dev, "会话的设备配置必须被清空")
	require.Equal(t, tun.OwnerLocal, owner, "清理完成后所有权必须回到本进程的默认值")
	require.False(t, a.currentConfig().Local.EnableTun2socks, "启用偏好必须落回 false")
	require.Equal(t, []tun.Owner{tun.OwnerLocal}, teardownOwners,
		"直连路径的拆除必须由本进程负责（跑关闭脚本、恢复 DNS）")

	select {
	case got := <-ui.tunFailures:
		require.ErrorIs(t, got, errStart, "界面必须收到启动失败的真实原因")
	default:
		t.Fatal("the UI was not told about the failed start")
	}
}

// TestFaultStopRacesWithStart 守住 tunMu 发布 manager 与派发 Start 之间的调度窗口：
// Stop 若看到"从未启动"直接返回，Start 仍会建起隧道，而再没人持有它去停。
func TestFaultStopRacesWithStart(t *testing.T) {
	a := newApp(&config.ClientConfig{}, "")
	a.sess.verifyTeardown = func(tun.DeviceConfig, tun.Owner, bool) error { return nil }

	const rounds = 50
	for range rounds {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			// 与生产路径一致：先登记 manager 再派发 Start。
			a.sess.tunMu.Lock()
			if a.sess.tunMgr != nil {
				a.sess.tunMu.Unlock()
				return
			}
			mgr := failedTunManager() // Start 会立刻失败，不需要真实设备
			a.sess.tunMgr = mgr
			a.sess.tunOwner = tun.OwnerLocal
			a.sess.tunMu.Unlock()
			a.sess.startTunEngine(mgr, "device")
		}()
		go func() {
			defer wg.Done()
			a.sess.tunDown()
		}()
		wg.Wait()

		// 等待可能迟到的失败回调完成回滚，再核对状态。
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			a.sess.tunMu.Lock()
			done := a.sess.tunMgr == nil
			a.sess.tunMu.Unlock()
			if done {
				break
			}
			time.Sleep(time.Millisecond)
		}

		a.sess.tunMu.Lock()
		remaining := a.sess.tunMgr
		a.sess.tunMu.Unlock()
		require.Nil(t, remaining,
			"并发之后不得留下无人持有的 manager：它会把引擎与路由一起留着")
	}
}

// TestFaultLeftoverRoutesAreRolledBack 注入最危险的一种失败：关闭脚本失败后残留的分流
// 默认路由仍指向没人读的设备，全机流量连同 DNS 一起黑洞（表现为"停 TUN 后断网"）。
func TestFaultLeftoverRoutesAreRolledBack(t *testing.T) {
	t.Run("residue is rolled back and the user is not bothered", func(t *testing.T) {
		a := newApp(&config.ClientConfig{}, "")
		ui := newStubAppUI()
		a.ui = ui

		probes, rollbacks := 0, 0
		ops := testTunOps(t)
		ops.probe = func(string, string) (string, bool) {
			probes++
			return "gateway: 198.18.0.1", probes == 1 // 回滚后干净
		}
		ops.rollback = func(tun.DeviceConfig) error {
			rollbacks++
			return nil
		}
		a.sess.verifyTeardown = ops.teardown
		a.sess.tunSession = &tun.DeviceConfig{Device: "utun9", TunGW: "198.18.0.1"}

		a.sess.tunDown()
		require.Equal(t, 1, rollbacks, "残留必须触发一次提权回滚")
		require.Equal(t, 2, probes, "回滚之后必须重新探测")
		select {
		case msg := <-ui.notices:
			t.Fatalf("回滚成功的拆除不该打扰用户，收到通知: %s", msg)
		default:
		}
	})

	t.Run("residue that survives the rollback is reported", func(t *testing.T) {
		a := newApp(&config.ClientConfig{}, "")
		ui := newStubAppUI()
		a.ui = ui

		ops := testTunOps(t)
		ops.probe = func(string, string) (string, bool) {
			return "gateway: 198.18.0.1", true // 一直残留
		}
		a.sess.verifyTeardown = ops.teardown
		a.sess.tunSession = &tun.DeviceConfig{Device: "utun9", TunGW: "198.18.0.1"}

		a.sess.tunDown()

		select {
		case msg := <-ui.notices:
			require.Contains(t, msg, "残留", "用户必须被告知路由仍然残留：这是断网的原因")
		default:
			t.Fatal("残留没有被上报给用户")
		}
	})
}

// TestFaultHelperOwnerSkipsLocalCleanup 是边界条件：helper 装的会话在拆除时，主进程
// 不得跑关闭脚本或恢复 DNS（那些归 helper）。本测试固定 session 侧确实把 OwnerHelper
// 传了下去——传错会让两条路径都以为自己该清理。
func TestFaultHelperOwnerSkipsLocalCleanup(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the helper path only exists on darwin/linux")
	}
	a := newApp(&config.ClientConfig{}, "")
	a.sess.tunSession = &tun.DeviceConfig{Device: "utun9", TunGW: "198.18.0.1"}
	a.sess.tunOwner = tun.OwnerHelper

	var gotOwner tun.Owner
	var gotSignalled bool
	a.sess.verifyTeardown = func(_ tun.DeviceConfig, owner tun.Owner, signalled bool) error {
		gotOwner, gotSignalled = owner, signalled
		return nil
	}

	// 真实的 FIFO 写端：拆除时要关掉它，helper 才能从 stdin 读到 EOF。
	fifo := filepath.Join(t.TempDir(), "helper.fifo")
	require.NoError(t, os.WriteFile(fifo, nil, 0o600))
	writer, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	require.NoError(t, err)
	a.sess.tunHelperStdin = writer

	a.sess.tunDown()

	require.Equal(t, tun.OwnerHelper, gotOwner, "helper 会话的拆除必须带着 helper 所有权")
	require.True(t, gotSignalled, "helper 会话必须先关 FIFO，才能等到它退出")
	require.Nil(t, a.sess.tunHelperStdin, "FIFO 写端必须被清空")
}
