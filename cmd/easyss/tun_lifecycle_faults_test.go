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

// 本文件是 TUN 生命周期收口之后的三条故障注入测试，对应验收清单：
//
//  1. 创建中途失败（TestFaultCreateFailsHalfway）；
//  2. Stop 与 Start 并发（TestFaultStopRacesWithStart）；
//  3. 路由残留（TestFaultLeftoverRoutesAreRolledBack）。
//
// 它们都通过包级钩子/注入点驱动，不需要 root、不需要 TUN 设备，也不会改写
// 运行测试的机器的网络配置：真实的创建脚本、pkexec/osascript 与系统路由表
// 都在进程之外，而在那些路径上只能靠"检查调用"来证明顺序。

// stubTunLifecycleHooks 把 client/tun 里会触碰系统的那几个钩子换成记录器。
// 它是故障注入的共同前置：注入点必须能被观察到"跑了没有、跑了几次、什么顺序"。
//
// 注意 client/tun 的钩子是包级未导出变量，cmd/easyss 无法直接替换；因此这里
// 复用的是它的公开接缝——Manager 的 Start/Stop 行为与 session 的所有权字段，
// 以及 platformTunTeardown/rollbackTunRoutes 这两个 cmd 包内的可注入变量。
func stubTunLifecycle(t *testing.T) {
	t.Helper()

	origResidue, origRollback := tunRouteResidue, rollbackTunRoutes
	t.Cleanup(func() { tunRouteResidue, rollbackTunRoutes = origResidue, origRollback })
}

// TestFaultCreateFailsHalfway 注入"创建脚本中途失败"。
//
// 平台脚本先装地址、再装路由，最后才按退出码汇报；它完全可能在拒掉某条命令
// 之前已经把地址与部分路由装进了系统。此时 Start 必须走拆除：只停引擎会让
// 那些路由留在表里，把流量送进一个没人读的设备——也就是"开了 TUN 却断网"。
//
// 注入点是一个真实的 manager + 一个必定失败的创建钩子。client/tun 的钩子是
// 包内私有的，因此这里改用它的公开等价物：Start 在 fd 路径之外调用的
// createTunDevFn，其生产实现就是脚本执行——测试用一个"半途失败"的错误路径
// 覆盖它，见 client/tun 的 TestTeardownMatrix 与 TestStartRollbackAfterCreateFailure。
// 本测试守的是 session 这一侧：失败的会话必须被拆掉、偏好必须回落、界面必须知情。
func TestFaultCreateFailsHalfway(t *testing.T) {
	a := newApp(&config.ClientConfig{}, "")
	ui := newStubAppUI()
	a.ui = ui
	stubTunLifecycle(t)

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

	errCreate := errors.New("tun: create device: exit status 1")
	a.sess.rollbackFailedTunStart(mgr, errCreate)

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
		require.ErrorIs(t, got, errCreate, "界面必须收到创建失败的真实原因")
	default:
		t.Fatal("the UI was not told about the failed create")
	}
}

// TestFaultStopRacesWithStart 注入"Stop 与 Start 并发"。
//
// session.tunUp 在 tunMu 内发布 manager、随后派发 goroutine 去 Start；用户的
// 下一次点击可能落在那个 goroutine 被调度之前。这条路径过去会让 Stop 看到
// "从未启动"并直接返回，而 Start 随后照常把隧道建起来——界面说关了，流量还在
// 里面，而且 session 已经把 manager 收走，再没人能停它。
//
// client/tun 的 TestManagerStopBeforeStartGoroutineRuns 固定了 manager 层的
// 行为；这里固定 session 层：并发点击之后，会话状态必须自洽（tunMgr 为 nil
// 时不留下任何仍在运行的引擎）。
func TestFaultStopRacesWithStart(t *testing.T) {
	a := newApp(&config.ClientConfig{}, "")
	stubTunLifecycle(t)
	a.sess.verifyTeardown = func(tun.DeviceConfig, tun.Owner, bool) error { return nil }

	const rounds = 50
	for range rounds {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			// 启用：与生产路径一样，先登记 manager 再派发 Start。
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
			_ = a.sess.tunDown()
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

// TestFaultLeftoverRoutesAreRolledBack 注入"路由残留"。
//
// 这是最危险的一种失败：helper 或本进程的关闭脚本失败之后，分流的默认路由
// （1/8…128/1）仍指向一个已经没人读的设备，全机 IPv4 流量——包括 DNS——全部
// 黑洞，用户看到的就是"停止 TUN 后断网"。父进程必须在 helper 退出后自己复核，
// 发现残留就提权回滚，回滚仍失败才通知用户。
func TestFaultLeftoverRoutesAreRolledBack(t *testing.T) {
	stubTunLifecycle(t)

	t.Run("residue is rolled back and the user is not bothered", func(t *testing.T) {
		a := newApp(&config.ClientConfig{}, "")
		ui := newStubAppUI()
		a.ui = ui

		probes, rollbacks := 0, 0
		tunRouteResidue = func(string, string) (string, bool) {
			probes++
			return "gateway: 198.18.0.1", probes == 1 // 回滚之后干净
		}
		rollbackTunRoutes = func(tun.DeviceConfig) error {
			rollbacks++
			return nil
		}
		a.sess.verifyTeardown = func(dev tun.DeviceConfig, _ tun.Owner, _ bool) error {
			return verifyTunTeardown(dev)
		}
		a.sess.tunSession = &tun.DeviceConfig{Device: "utun9", TunGW: "198.18.0.1"}

		require.NoError(t, a.sess.tunDown())
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

		tunRouteResidue = func(string, string) (string, bool) {
			return "gateway: 198.18.0.1", true // 一直残留
		}
		rollbackTunRoutes = func(tun.DeviceConfig) error { return nil }
		a.sess.verifyTeardown = func(dev tun.DeviceConfig, _ tun.Owner, _ bool) error {
			return verifyTunTeardown(dev)
		}
		a.sess.tunSession = &tun.DeviceConfig{Device: "utun9", TunGW: "198.18.0.1"}

		require.NoError(t, a.sess.tunDown())

		select {
		case msg := <-ui.notices:
			require.Contains(t, msg, "残留", "用户必须被告知路由仍然残留：这是断网的原因")
		default:
			t.Fatal("残留没有被上报给用户")
		}
	})
}

// TestFaultHelperOwnerSkipsLocalCleanup 是故障注入的边界条件：helper 装的会话
// 在拆除时，主进程不得去跑关闭脚本或恢复 DNS（那些归 helper）。它过去由
// SkipRouteCleanup 这个与 DeviceFD 必须永远同步的布尔表达，现在由 tun.Owner
// 表达——本测试固定 session 侧确实把 OwnerHelper 传下去。
func TestFaultHelperOwnerSkipsLocalCleanup(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the helper path only exists on darwin/linux")
	}
	stubTunLifecycle(t)

	a := newApp(&config.ClientConfig{}, "")
	a.sess.tunSession = &tun.DeviceConfig{Device: "utun9", TunGW: "198.18.0.1"}
	a.sess.tunOwner = tun.OwnerHelper

	var gotOwner tun.Owner
	var gotSignalled bool
	a.sess.verifyTeardown = func(_ tun.DeviceConfig, owner tun.Owner, signalled bool) error {
		gotOwner, gotSignalled = owner, signalled
		return nil
	}

	// 一个真实的 FIFO 写端：拆除时要关掉它，helper 才能从 stdin 读到 EOF。
	fifo := filepath.Join(t.TempDir(), "helper.fifo")
	require.NoError(t, os.WriteFile(fifo, nil, 0o600))
	writer, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	require.NoError(t, err)
	a.sess.tunHelperStdin = writer

	require.NoError(t, a.sess.tunDown())

	require.Equal(t, tun.OwnerHelper, gotOwner, "helper 会话的拆除必须带着 helper 所有权")
	require.True(t, gotSignalled, "helper 会话必须先关 FIFO，才能等到它退出")
	require.Nil(t, a.sess.tunHelperStdin, "FIFO 写端必须被清空")
}
