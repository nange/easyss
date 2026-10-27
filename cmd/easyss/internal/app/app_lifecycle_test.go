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

// TestAdoptTunManagerBindsDialerBeforeForwarding 守住两个 TUN 状态的不同边：adopt 时引擎还没
// 转发（forward DNS 必须拒答），但路由可能已经装好，直连拨号必须已绑定物理接口，否则会回环。
func TestAdoptTunManagerBindsDialerBeforeForwarding(t *testing.T) {
	core := &runner.Core{Client: &client.Client{}}
	a := New(&clientconfig.ClientConfig{}, "")
	a.sess.installCore(core)

	a.sess.tunMu.Lock()
	a.sess.adoptTunManager(&tun.Manager{}, nil, tun.OwnerLocal)
	a.sess.tunMu.Unlock()

	require.False(t, core.Client.TunForwardingEnabled(), "引擎起来之前 forward DNS 必须拒答")
	require.True(t, core.Client.TunModeEnabled(), "adopt 之后直连拨号必须保持绑定")
}

// TestTunDownKeepsDialerBoundUntilRoutesAreGone 守住拆除期的两条边：forward DNS 在拆除一开始
// 就拒答，拨号器一直绑定到 tunMgr 清空（关闭脚本删完路由）之后，否则新建直连会跌进隧道。
func TestTunDownKeepsDialerBoundUntilRoutesAreGone(t *testing.T) {
	core := &runner.Core{Client: &client.Client{}}
	a := New(&clientconfig.ClientConfig{}, "")
	a.sess.installCore(core)

	dev := tun.DeviceConfig{}
	a.sess.tunMu.Lock()
	a.sess.tunMgr = &tun.Manager{}
	a.sess.tunSession = &dev
	a.sess.tunActive = true
	a.sess.syncTunStateLocked()
	a.sess.tunMu.Unlock()
	require.True(t, core.Client.TunForwardingEnabled())
	require.True(t, core.Client.TunModeEnabled())

	// verifyTeardown 在 mgr.Stop() 之后运行：那一刻 forward DNS 必须已拒答，拨号器还不能解绑。
	checked, forwardingAtTeardown, boundAtTeardown := false, true, false
	a.sess.verifyTeardown = func(tun.DeviceConfig, tun.Owner, bool) error {
		checked = true
		forwardingAtTeardown = core.Client.TunForwardingEnabled()
		boundAtTeardown = core.Client.TunModeEnabled()
		return nil
	}

	a.sess.tunDown()

	require.True(t, checked)
	require.False(t, forwardingAtTeardown, "拆除开始前 forward DNS 必须已经拒答")
	require.True(t, boundAtTeardown, "路由删完前直连拨号必须保持绑定")
	require.False(t, core.Client.TunForwardingEnabled())
	require.False(t, core.Client.TunModeEnabled())
}

// TestMarkTunEngineUpOpensForwarding 守住唯一的开闸点：只有 Manager.Start 成功且 manager 仍是
// 当前会话时才放行 forward DNS；被替换掉的会话迟到的成功回调不得开闸。
func TestMarkTunEngineUpOpensForwarding(t *testing.T) {
	core := &runner.Core{Client: &client.Client{}}
	a := New(&clientconfig.ClientConfig{}, "")
	a.updateConfig(func(c *clientconfig.ClientConfig) { c.Local.EnableForwardDNS = true })
	a.sess.installCore(core)

	mgr := &tun.Manager{}
	a.sess.tunMu.Lock()
	a.sess.adoptTunManager(mgr, nil, tun.OwnerLocal)
	a.sess.tunMu.Unlock()
	require.False(t, core.Client.TunForwardingEnabled(), "adopt 本身不得开闸")

	a.sess.markTunEngineUp(mgr)
	require.True(t, core.Client.TunForwardingEnabled(), "Manager.Start 成功后必须放行 forward DNS")
	require.True(t, core.Client.TunModeEnabled(), "开闸不得解绑直连拨号器")

	// 用户关掉又重开 TUN：旧 manager 迟到的成功回调不能给新会话开闸。
	next := &tun.Manager{}
	a.sess.tunMu.Lock()
	a.sess.adoptTunManager(next, nil, tun.OwnerLocal)
	a.sess.tunMu.Unlock()
	a.sess.markTunEngineUp(mgr)
	require.False(t, core.Client.TunForwardingEnabled(), "过期 manager 不得开闸")
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
