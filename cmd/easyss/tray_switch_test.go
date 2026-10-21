//go:build !headless

package main

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gogpu/systray"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/runner"
	"github.com/stretchr/testify/require"
)

// newSwitchTestApp 构建一个最小 TrayApp：切换逻辑只用到服务器菜单、代理对象菜单、
// 当前配置快照与当前核心，既不需要托盘，也不需要核心或网络。
func newSwitchTestApp(t *testing.T) *TrayApp {
	t.Helper()

	cfg := &config.ClientConfig{Servers: []*config.ServerProfile{
		{Host: "a.example", Port: 443, Default: true},
		{Host: "b.example", Port: 443},
	}}
	a := &TrayApp{App: newApp(cfg, "")}
	a.ui = a
	a.server = newServerMenu(systray.NewMenu(), cfg, func(int) {})
	a.object = newProxyObjectMenu(systray.NewMenu(), cfg, func() {}, func() {})
	return a
}

// TestSwitchServerRestoresTheRunningSelectionOnFailure 固定"切换失败不能把用户
// 留在没有任何服务器被选中"的契约：restartService 已经尽力把服务回滚到切换前的
// 服务器（因此 a.cfg 仍指向它、核心也还在），菜单必须跟着回到那一个。
func TestSwitchServerRestoresTheRunningSelectionOnFailure(t *testing.T) {
	a := newSwitchTestApp(t)
	a.sess.installCore(&runner.Core{}) // 回滚成功：仍有 core 在运行

	errBoom := errors.New("boom")
	var switchedTo string
	err := a.switchServer(1, func(cfg *config.ClientConfig) error {
		switchedTo = cfg.DefaultServerAddr()
		return errBoom
	})

	require.ErrorIs(t, err, errBoom)
	require.Equal(t, "b.example:443", switchedTo, "切换目标必须由下标决定")
	require.True(t, a.server.items[0].IsChecked(),
		"切换失败后菜单必须还原到仍在运行的服务器")
	require.False(t, a.server.items[1].IsChecked())
}

// TestSwitchServerLeavesNothingCheckedWhenTheCoreIsGone 覆盖回滚也失败的情形：
// 此时没有任何服务在运行，菜单不能声称某个服务器已选中——那正是用户看到的
// "切换失败 + 本机断网"。
func TestSwitchServerLeavesNothingCheckedWhenTheCoreIsGone(t *testing.T) {
	a := newSwitchTestApp(t)

	err := a.switchServer(1, func(*config.ClientConfig) error {
		return errors.New("boom")
	})

	require.Error(t, err)
	require.False(t, a.server.items[0].IsChecked())
	require.False(t, a.server.items[1].IsChecked())
}

// TestSwitchServerMarksTheTargetOnSuccess 确认成功路径把勾选落在目标服务器上。
func TestSwitchServerMarksTheTargetOnSuccess(t *testing.T) {
	a := newSwitchTestApp(t)

	// 与生产 restartService 一致：由 restart 把"目标服务器"这条增量发布出去
	//（生产实现见 restartServiceInSequence；这里省略真正的 Start）。
	require.NoError(t, a.switchServer(1, func(cfg *config.ClientConfig) error {
		targetIdx := cfg.DefaultServerIndex()
		a.updateConfig(func(c *config.ClientConfig) { c.SetDefaultServerIndex(targetIdx) })
		return nil
	}))

	require.Equal(t, "b.example:443", a.currentConfig().DefaultServerAddr())
	require.False(t, a.server.items[0].IsChecked())
	require.True(t, a.server.items[1].IsChecked())
}

// TestSwitchServerSkipsAServerThatIsAlreadyRunning 覆盖"排队期间状态已经变了"：
// 连点同一个服务器不该再停一次、起一次服务，只需要把勾选确认回来。
func TestSwitchServerSkipsAServerThatIsAlreadyRunning(t *testing.T) {
	a := newSwitchTestApp(t)
	a.sess.installCore(&runner.Core{})

	called := false
	require.NoError(t, a.switchServer(0, func(*config.ClientConfig) error {
		called = true
		return nil
	}))

	require.False(t, called, "已经在运行的服务器不该再重启一次")
	require.True(t, a.server.items[0].IsChecked())
}

// TestSwitchServerSerializesConcurrentSwitches 守住串行化：托盘每次点击都新起 goroutine，
// 并发执行两套"停服务 → 起服务"会让配置互相覆盖，甚至留下没有 core 在运行的状态。
func TestSwitchServerSerializesConcurrentSwitches(t *testing.T) {
	a := newSwitchTestApp(t)

	var (
		mu        sync.Mutex
		active    int
		maxActive int
	)
	started := make(chan struct{}, 3)
	release := make(chan struct{})

	restart := func(*config.ClientConfig) error {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()

		started <- struct{}{}
		<-release

		mu.Lock()
		active--
		mu.Unlock()
		return nil
	}

	var wg sync.WaitGroup
	for i := range 3 {
		wg.Go(func() {
			_ = a.switchServer(i, restart)
		})
	}

	// 等第一个真的进入 restart，再给"未串行化"的实现一点时间暴露重叠：
	// 断言发生在放行之前，因此串行化实现里根本不可能有第二个进来。
	<-started
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	overlap := maxActive
	mu.Unlock()
	require.Equal(t, 1, overlap, "并发的服务器切换必须被串行化")

	close(release)
	wg.Wait()
}

// TestRestartServiceRollsBackToThePreviousServer 固定"新服务器起不来就退回旧
// 服务器"的契约：新服务器起不来时必须退回旧服务器，否则用户会停在旧服务已停、
// （本地端口没人监听，系统代理还指着它），也就是"切换失败并且断网"。
func TestRestartServiceRollsBackToThePreviousServer(t *testing.T) {
	a := newSwitchTestApp(t)
	// newSwitchTestApp 的系统代理项默认勾选，才能验证回滚之后它被恢复回来。
	applied, reverts := stubSysProxy(a.App, nil)
	a.updateConfig(func(c *config.ClientConfig) { c.Local.HTTPPort = 5080 })

	errBoom := errors.New("listen tcp 127.0.0.1:4080: bind: address already in use")
	var started []string
	start := func(cfg *config.ClientConfig) error {
		started = append(started, cfg.DefaultServerAddr())
		if cfg.DefaultServerAddr() == "b.example:443" {
			return errBoom
		}
		// 生产实现不再换装配置（restartServiceInSequence 已经把增量发布出去），
		// 因此这里也不 adopt：换装会把并发菜单改动覆盖掉。
		return nil
	}

	next := a.currentConfig().Clone()
	next.SetDefaultServerIndex(1)
	err := a.restartServiceWith(next, start)

	require.ErrorIs(t, err, errBoom)
	require.Equal(t, []string{"b.example:443", "a.example:443"}, started,
		"切换失败后必须用切换前的配置再起一次")
	require.Equal(t, "a.example:443", a.currentConfig().DefaultServerAddr())
	require.GreaterOrEqual(t, *reverts, 1, "closeService 必须先把系统代理撤下来")
	require.Equal(t, []string{"127.0.0.1:5080"}, *applied,
		"回滚成功后必须把系统代理恢复回来，且地址来自当前配置的本地 HTTP 入口")
}

// TestRestartServiceReportsBothFailures 覆盖回滚也失败的情形：两个错误都要上报，
// 调用方才能判断"现在完全没有服务在运行"。
func TestRestartServiceReportsBothFailures(t *testing.T) {
	a := newSwitchTestApp(t)
	stubSysProxy(a.App, nil)

	errSwitch := errors.New("switch failed")
	errRollback := errors.New("rollback failed")
	start := func(cfg *config.ClientConfig) error {
		if cfg.DefaultServerAddr() == "b.example:443" {
			return errSwitch
		}
		return errRollback
	}

	next := a.currentConfig().Clone()
	next.SetDefaultServerIndex(1)
	err := a.restartServiceWith(next, start)

	require.ErrorIs(t, err, errSwitch)
	require.ErrorIs(t, err, errRollback)
	require.Contains(t, err.Error(), "rollback to a.example:443")
}

// TestRestartServiceDoesNotClobberMenuChangesFromAStaleTarget 守住丢更新：closeService 在
// macOS 上要等 TUN 拆除的管理员凭据（可达数秒），这期间用户改的菜单项不能被旧快照静默回滚。
func TestRestartServiceDoesNotClobberMenuChangesFromAStaleTarget(t *testing.T) {
	a := newSwitchTestApp(t)
	stubRunCore(a.App)
	stubSysProxy(a.App, nil)
	t.Cleanup(a.Stop)

	// 停服务期间的菜单点击：撤销系统代理是 closeService 的必经步骤，把这次
	// 改动挂在那里，就精确落进了"目标配置已取好、但还没起服务"的窗口。
	revert := a.deps.sysProxyRevert
	a.deps.sysProxyRevert = func() error {
		a.updateConfig(func(c *config.ClientConfig) { c.Routing.ProxyRule = "direct" })
		return revert()
	}

	// 目标配置在这之前就取好了（生产里由 switchServer 取），因此对那次切换而言
	// 这份代理规则是"新"的。
	next := a.currentConfig().Clone()
	next.SetDefaultServerIndex(1)

	require.NoError(t, a.restartServiceWith(next, a.startService))

	require.Equal(t, "b.example:443", a.currentConfig().DefaultServerAddr(),
		"切换必须生效")
	require.Equal(t, "direct", a.currentConfig().Routing.ProxyRule,
		"停服务期间的菜单改动不得被切换前取的旧快照覆盖")
}

// TestRestartServiceRollbackKeepsMenuChanges 是上一条的回滚分支：回滚同样只
// 回退"服务器选择 + TUN 偏好"两条增量，保留菜单在这期间的最新改动。
func TestRestartServiceRollbackKeepsMenuChanges(t *testing.T) {
	a := newSwitchTestApp(t)
	stubSysProxy(a.App, nil)
	t.Cleanup(a.Stop)

	errBoom := errors.New("new server failed")
	prevRunCore := a.deps.runCore
	a.deps.runCore = func(cfg *config.ClientConfig) (*runner.Core, error) {
		if cfg.DefaultServerAddr() == "b.example:443" {
			// 新服务器起不来的这一刻，用户改了日志级别。
			a.updateConfig(func(c *config.ClientConfig) { c.Log.Level = "debug" })
			return nil, errBoom
		}
		return &runner.Core{}, nil
	}
	t.Cleanup(func() { a.deps.runCore = prevRunCore })

	next := a.currentConfig().Clone()
	next.SetDefaultServerIndex(1)

	err := a.restartServiceWith(next, a.startService)

	require.ErrorIs(t, err, errBoom)
	require.Equal(t, "a.example:443", a.currentConfig().DefaultServerAddr(),
		"回滚后配置必须指回原服务器")
	require.Equal(t, "debug", a.currentConfig().Log.Level,
		"回滚不得覆盖菜单的最新改动")
}

// TestSwitchServerIsRaceFreeWithStatsReads 守住切换与后台统计读当前核心的数据竞争
// （-race 下回归）：当前核心由 session.core 原子发布，两边各自读快照。
func TestSwitchServerIsRaceFreeWithStatsReads(t *testing.T) {
	a := newSwitchTestApp(t)
	stubRunCore(a.App)
	a.sess.installCore(&runner.Core{})

	restart := func(cfg *config.ClientConfig) error {
		a.Stop()
		targetIdx := cfg.DefaultServerIndex()
		a.updateConfig(func(c *config.ClientConfig) { c.SetDefaultServerIndex(targetIdx) })
		return a.Start()
	}

	var wg sync.WaitGroup
	stopReading := make(chan struct{})
	for range 3 {
		wg.Go(func() {
			for {
				select {
				case <-stopReading:
					return
				default:
				}
				a.sess.logStatsOnce()
			}
		})
	}

	writeErr := make(chan error, 1)
	wg.Go(func() {
		defer close(stopReading)
		for i := range 20 {
			if err := a.switchServer(i%2, restart); err != nil {
				writeErr <- err
				return
			}
		}
	})

	wg.Wait()
	select {
	case err := <-writeErr:
		t.Fatalf("switchServer: %v", err)
	default:
	}
	require.NotNil(t, a.currentCore(), "最后一次切换之后服务必须在运行")
}

// TestCloseServiceIsSerializedWithSwitches 守住退出拆除（closeService）与切换的"停→起"
// 不交错：互斥只由会话序列锁提供，托盘本身不持锁。
func TestCloseServiceIsSerializedWithSwitches(t *testing.T) {
	a := newSwitchTestApp(t)
	stubSysProxy(a.App, nil)

	entered := make(chan struct{})
	release := make(chan struct{})
	restart := func(*config.ClientConfig) error {
		close(entered)
		<-release
		return nil
	}

	switched := make(chan struct{})
	go func() {
		defer close(switched)
		_ = a.switchServer(1, restart)
	}()
	<-entered

	exited := make(chan struct{})
	go func() {
		defer close(exited)
		a.closeService()
	}()

	select {
	case <-exited:
		t.Fatal("closeService 与切换并发执行了：退出拆除必须在会话序列锁上排队")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	<-switched
	<-exited
}
