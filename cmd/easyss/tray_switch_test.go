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

// newSwitchTestApp 构建一个只包含"选择服务器"菜单的最小 TrayApp：切换逻辑只用到
// serverAddrs/serverMenuItems/a.cfg/当前核心，既不需要托盘，也不需要核心或网络。
func newSwitchTestApp(t *testing.T) *TrayApp {
	t.Helper()

	cfg := &config.ClientConfig{Servers: []*config.ServerProfile{
		{Address: "a.example", Port: 443, Default: true},
		{Address: "b.example", Port: 443},
	}}
	a := &TrayApp{App: &App{cfg: cfg}}
	a.serverAddrs = cfg.ServerListAddrs()

	menu := systray.NewMenu()
	for i, addr := range a.serverAddrs {
		a.serverMenuItems = append(a.serverMenuItems, menu.AddCheckbox(addr, i == 0, nil))
	}
	return a
}

// TestSwitchServerRestoresTheRunningSelectionOnFailure 固定"切换失败不能把用户
// 留在没有任何服务器被选中"的契约：restartService 已经尽力把服务回滚到切换前的
// 服务器（因此 a.cfg 仍指向它、核心也还在），菜单必须跟着回到那一个。
func TestSwitchServerRestoresTheRunningSelectionOnFailure(t *testing.T) {
	a := newSwitchTestApp(t)
	a.installCore(&runner.Core{}) // 回滚成功：仍有 core 在运行

	errBoom := errors.New("boom")
	var switchedTo string
	err := a.switchServer(1, func(cfg *config.ClientConfig) error {
		switchedTo = cfg.DefaultServerAddr()
		return errBoom
	})

	require.ErrorIs(t, err, errBoom)
	require.Equal(t, "b.example:443", switchedTo, "切换目标必须由下标决定")
	require.True(t, a.serverMenuItems[0].IsChecked(),
		"切换失败后菜单必须还原到仍在运行的服务器")
	require.False(t, a.serverMenuItems[1].IsChecked())
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
	require.False(t, a.serverMenuItems[0].IsChecked())
	require.False(t, a.serverMenuItems[1].IsChecked())
}

// TestSwitchServerMarksTheTargetOnSuccess 确认成功路径把勾选落在目标服务器上。
func TestSwitchServerMarksTheTargetOnSuccess(t *testing.T) {
	a := newSwitchTestApp(t)

	require.NoError(t, a.switchServer(1, func(cfg *config.ClientConfig) error {
		// 生产代码里 restartService 会通过 adoptConfig 把新配置装回 App，
		// 这里模拟这一步。
		a.adoptConfig(cfg)
		return nil
	}))

	require.False(t, a.serverMenuItems[0].IsChecked())
	require.True(t, a.serverMenuItems[1].IsChecked())
}

// TestSwitchServerSkipsAServerThatIsAlreadyRunning 覆盖"排队期间状态已经变了"：
// 连点同一个服务器不该再停一次、起一次服务，只需要把勾选确认回来。
func TestSwitchServerSkipsAServerThatIsAlreadyRunning(t *testing.T) {
	a := newSwitchTestApp(t)
	a.installCore(&runner.Core{})

	called := false
	require.NoError(t, a.switchServer(0, func(*config.ClientConfig) error {
		called = true
		return nil
	}))

	require.False(t, called, "已经在运行的服务器不该再重启一次")
	require.True(t, a.serverMenuItems[0].IsChecked())
}

// TestSwitchServerSerializesConcurrentSwitches 固定串行化契约：托盘的每次点击
// 都会新起一个 goroutine，而一次切换是整套"停服务 → 起服务"（抢同一组本地端口
// 4080/5080）。并发执行两套会让 a.cfg 互相覆盖，甚至留下没有任何 core
// 在运行的状态。
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
// 服务器"的契约：失败的切换过去会把用户留在旧服务已停、新服务没起来的状态
// （本地端口没人监听，系统代理还指着它），也就是"切换失败并且断网"。
func TestRestartServiceRollsBackToThePreviousServer(t *testing.T) {
	a := newSwitchTestApp(t)
	// 系统代理开着，才能验证回滚之后它被恢复回来。
	a.SetBrowserMenu(systray.NewMenu().AddCheckbox("系统代理", true, nil))
	applied, reverts := stubSysProxy(t, nil)

	errBoom := errors.New("listen tcp 127.0.0.1:4080: bind: address already in use")
	var started []string
	start := func(cfg *config.ClientConfig) error {
		started = append(started, cfg.DefaultServerAddr())
		if cfg.DefaultServerAddr() == "b.example:443" {
			return errBoom
		}
		a.adoptConfig(cfg)
		return nil
	}

	next := a.cfg.Clone()
	next.SetDefaultServerIndex(1)
	err := a.restartServiceWith(next, start)

	require.ErrorIs(t, err, errBoom)
	require.Equal(t, []string{"b.example:443", "a.example:443"}, started,
		"切换失败后必须用切换前的配置再起一次")
	require.Equal(t, "a.example:443", a.cfg.DefaultServerAddr())
	require.GreaterOrEqual(t, *reverts, 1, "closeService 必须先把系统代理撤下来")
	require.Equal(t, []int{a.cfg.Local.HTTPPort}, *applied,
		"回滚成功后必须把系统代理恢复回来")
}

// TestRestartServiceReportsBothFailures 覆盖回滚也失败的情形：两个错误都要上报，
// 调用方才能判断"现在完全没有服务在运行"。
func TestRestartServiceReportsBothFailures(t *testing.T) {
	a := newSwitchTestApp(t)
	stubSysProxy(t, nil)

	errSwitch := errors.New("switch failed")
	errRollback := errors.New("rollback failed")
	start := func(cfg *config.ClientConfig) error {
		if cfg.DefaultServerAddr() == "b.example:443" {
			return errSwitch
		}
		return errRollback
	}

	next := a.cfg.Clone()
	next.SetDefaultServerIndex(1)
	err := a.restartServiceWith(next, start)

	require.ErrorIs(t, err, errSwitch)
	require.ErrorIs(t, err, errRollback)
	require.Contains(t, err.Error(), "rollback to a.example:443")
}

// TestSwitchServerIsRaceFreeWithStatsReads 固定"切换服务器与后台统计读取不再
// 竞争当前核心"：-race 下这是回归测试（旧实现里 App.Start 无锁写 a.core，
// switchServer 与 statsLoop 无锁读同一个普通字段）。restart 复用真实的
// Start/Stop 与 adoptConfig，等价于生产 restartService，只把核心换成注入的
// 零值核心。
func TestSwitchServerIsRaceFreeWithStatsReads(t *testing.T) {
	stubRunCore(t)
	a := newSwitchTestApp(t)
	a.installCore(&runner.Core{})

	restart := func(cfg *config.ClientConfig) error {
		a.Stop()
		a.adoptConfig(cfg)
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
				a.logStatsOnce()
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
