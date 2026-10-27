package app

import (
	"errors"
	"sync"
	"testing"

	"github.com/nange/easyss/v3/client"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/runner"
	"github.com/stretchr/testify/require"
)

// stubRunCore 注入零值核心，使测试能并发驱动真实的 App.Start/App.Stop 而不监听端口。
// 零值核心对 Stop 安全：runner.Core.cleanup 每一步都有 nil 守卫。
func stubRunCore(a *App) {
	a.deps.runCore = func(*clientconfig.ClientConfig) (*runner.Core, error) { return &runner.Core{}, nil }
}

// TestAppStartStopIsRaceFree 固定"核心读写拿到的是一致快照"：两次独立的非原子读之间被
// Stop 清空会直接 nil 解引用，-race 下最先暴露。核心由 session.core 原子发布。
func TestAppStartStopIsRaceFree(t *testing.T) {
	a := New(&clientconfig.ClientConfig{}, "")
	stubRunCore(a)

	var wg sync.WaitGroup
	stopReading := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stopReading:
					return
				default:
				}
				a.sess.logStatsOnce()
				if core := a.currentCore(); core != nil {
					_ = core.Client
				}
			}
		})
	}

	writeErr := make(chan error, 1)
	wg.Go(func() {
		defer close(stopReading)
		for range 200 {
			if err := a.Start(); err != nil {
				writeErr <- err
				return
			}
			a.Stop()
		}
	})

	wg.Wait()
	select {
	case err := <-writeErr:
		t.Fatalf("Start/Stop: %v", err)
	default:
	}
	require.Nil(t, a.currentCore(), "全部 Stop 之后不应还有核心")
}

// TestAppStopIsConcurrentAndIdempotent 固定"取下即停"的幂等语义：并发与顺序的重复 Stop
// 只能取下核心一次，其余是空操作；会话重启因此不必整体重建 App 来重置一次性状态。
func TestAppStopIsConcurrentAndIdempotent(t *testing.T) {
	a := New(&clientconfig.ClientConfig{}, "")
	a.sess.installCore(&runner.Core{})

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(a.Stop)
	}
	wg.Wait()
	a.Stop() // 顺序重复调用同样安全

	require.Nil(t, a.currentCore())
}

// TestAppStartResetsSessionState 固定"每次 Start 重置会话级状态"：漏掉的话上一轮的启动
// 警告会既抑制新一轮记录（只在 nil 时写入），又被 restartServiceInSequence 重复上报。
func TestAppStartResetsSessionState(t *testing.T) {
	a := New(&clientconfig.ClientConfig{}, "")
	stubRunCore(a)
	a.sess.mu.Lock()
	a.sess.startupWarn = errors.New("stale warning")
	a.sess.tunSkippedForNetwork = true
	a.sess.mu.Unlock()

	require.NoError(t, a.Start())
	t.Cleanup(a.Stop)

	require.Nil(t, a.currentStartupWarn())
	a.sess.mu.Lock()
	skipped := a.sess.tunSkippedForNetwork
	a.sess.mu.Unlock()
	require.False(t, skipped)
}

// TestAppStartupWarnAccessIsRaceFree 固定 startupWarn 的读侧契约：它由 session.start 在会话锁下
// 写，而 restartServiceInSequence 与那次 start 不同 goroutine，必须走 currentStartupWarn()。
func TestAppStartupWarnAccessIsRaceFree(t *testing.T) {
	a := New(&clientconfig.ClientConfig{}, "")
	stubRunCore(a)

	var wg sync.WaitGroup
	stopReading := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stopReading:
					return
				default:
				}
				_ = a.currentStartupWarn()
			}
		})
	}

	wg.Go(func() {
		defer close(stopReading)
		for range 200 {
			if err := a.Start(); err != nil {
				return
			}
			a.Stop()
		}
	})

	wg.Wait()
	require.Nil(t, a.currentStartupWarn())
}

// TestUpdateConfigIsRaceFreeAndLossless 固定配置快照的 copy-on-write 契约：并发读者与发布
// 不得竞争，且 updateConfig 的读改写必须原子，否则并发发布者互相覆盖丢增量（N 个写者各 +1 应恰好 N*M）。
func TestUpdateConfigIsRaceFreeAndLossless(t *testing.T) {
	const writers, perWriter = 4, 200
	a := New(&clientconfig.ClientConfig{}, "")

	var writersWG sync.WaitGroup
	start := make(chan struct{})
	for range writers {
		writersWG.Go(func() {
			<-start
			for range perWriter {
				a.updateConfig(func(c *clientconfig.ClientConfig) { c.Timeout++ })
			}
		})
	}

	var readersWG sync.WaitGroup
	stopReading := make(chan struct{})
	for range 2 {
		readersWG.Go(func() {
			for {
				select {
				case <-stopReading:
					return
				default:
				}
				if snap := a.currentConfig(); snap != nil {
					_ = snap.Clone()
					_ = snap.Local.HTTPPort
				}
			}
		})
	}

	close(start)
	writersWG.Wait()
	close(stopReading)
	readersWG.Wait()

	require.Equal(t, writers*perWriter, a.currentConfig().Timeout,
		"并发发布不得丢失更新（CAS 循环应精确累计）")
}

// TestAppStopTakesTheTunManager 固定 Stop 收走当前的 TUN manager：漏掉它意味着那个引擎的
// 分流路由会留在系统路由表里无人回收。
func TestAppStopTakesTheTunManager(t *testing.T) {
	a := New(&clientconfig.ClientConfig{}, "")

	// 零值 manager 的 Stop 是安全空操作（running 为 false），无需真实设备。
	a.sess.tunMu.Lock()
	a.sess.tunMgr = &tun.Manager{}
	a.sess.tunMu.Unlock()

	a.Stop()

	a.sess.tunMu.Lock()
	defer a.sess.tunMu.Unlock()
	require.Nil(t, a.sess.tunMgr, "Stop 必须停掉并清空 TUN manager")
}

// TestAdoptTunManagerDoesNotEnableTunMode 守住"adopt 不等于 TUN 已生效"：设备、路由与引擎
// 都还没起时置位，forward DNS 会在启动窗口里把上游查询从物理网卡直连出去（DNS 泄漏）。
func TestAdoptTunManagerDoesNotEnableTunMode(t *testing.T) {
	core := &runner.Core{Client: &client.Client{}}
	a := New(&clientconfig.ClientConfig{}, "")
	a.sess.installCore(core)
	core.Client.SetTunMode(true) // client.New 按配置初值播种的状态

	a.sess.tunMu.Lock()
	a.sess.adoptTunManager(&tun.Manager{}, nil, tun.OwnerLocal)
	a.sess.tunMu.Unlock()

	require.False(t, core.Client.TunModeEnabled())
}

// TestTunDownClearsTunModeBeforeTeardown 守住运行期状态的撤除时机：拆除一开始就得置 false，
// 否则关闭脚本删掉路由之后、tunDown 返回之前，forward DNS 仍会认为上游查询会进入隧道。
func TestTunDownClearsTunModeBeforeTeardown(t *testing.T) {
	core := &runner.Core{Client: &client.Client{}}
	a := New(&clientconfig.ClientConfig{}, "")
	a.sess.installCore(core)

	dev := tun.DeviceConfig{}
	a.sess.tunMu.Lock()
	a.sess.tunMgr = &tun.Manager{}
	a.sess.tunSession = &dev
	a.sess.tunActive = true
	a.sess.syncTunModeLocked()
	a.sess.tunMu.Unlock()
	require.True(t, core.Client.TunModeEnabled())

	// verifyTeardown 在 mgr.Stop() 之后运行：那一刻状态必须已经是 false。
	checked, activeAtTeardown := false, true
	a.sess.verifyTeardown = func(tun.DeviceConfig, tun.Owner, bool) error {
		checked = true
		activeAtTeardown = core.Client.TunModeEnabled()
		return nil
	}

	a.sess.tunDown()

	require.True(t, checked)
	require.False(t, activeAtTeardown, "拆除开始前必须已经撤销运行期状态")
	require.False(t, core.Client.TunModeEnabled())
}

// TestAppStopAndTunToggleAreRaceFree 固定 tunMgr 的锁契约：托盘的 TUN 开关、启动期的
// startTunEngineAtStartup 与停止期的 stop 必须共用 session.tunMu 读写 tunMgr，任一方脱锁 -race 即暴露。
func TestAppStopAndTunToggleAreRaceFree(t *testing.T) {
	a := New(&clientconfig.ClientConfig{}, "")

	var wg sync.WaitGroup
	stopToggling := make(chan struct{})
	for range 3 {
		wg.Go(func() {
			for {
				select {
				case <-stopToggling:
					return
				default:
				}
				a.sess.tunMu.Lock()
				if a.currentCore() != nil && a.sess.tunMgr == nil {
					a.sess.tunMgr = &tun.Manager{}
				}
				a.sess.tunMu.Unlock()
			}
		})
	}

	wg.Go(func() {
		defer close(stopToggling)
		for range 200 {
			a.sess.installCore(&runner.Core{})
			a.Stop()
		}
	})

	wg.Wait()
	require.Nil(t, a.currentCore(), "全部 Stop 之后不应还有核心")
}
