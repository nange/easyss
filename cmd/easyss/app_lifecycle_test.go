package main

import (
	"errors"
	"sync"
	"testing"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/runner"
	"github.com/stretchr/testify/require"
)

// stubRunCore 注入一个零值核心，使测试可以并发驱动真实的 App.Start/App.Stop
// 与后台统计读取，而不必监听本地端口或连网络。零值核心对 Stop 是安全的：
// runner.Core.cleanup 的每一步都有 nil 守卫（见 closeDone 与各字段判断）。
func stubRunCore(t *testing.T) {
	t.Helper()
	prev := runCore
	runCore = func(*config.ClientConfig) (*runner.Core, error) { return &runner.Core{}, nil }
	t.Cleanup(func() { runCore = prev })
}

// TestAppStartStopIsRaceFree 固定"Start/Stop 改写当前核心时，读者拿到的是一致
// 快照"。-race 下这是回归测试：过去当前核心是普通字段，Stop 写 nil 与统计循环/
// 托盘处理器的无锁读构成数据竞争，而 `core != nil && core.Client != nil` 这类
// 两次读之间被清空会直接 nil 解引用（现在它由 session.core 原子发布）。
func TestAppStartStopIsRaceFree(t *testing.T) {
	stubRunCore(t)
	a := newApp(&config.ClientConfig{}, "")

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
				// 托盘处理器的读法：先取一次快照，再判断快照内部的字段。
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

// TestAppStopIsConcurrentAndIdempotent 固定"取下即停"的幂等语义：并发的多个
// Stop 与随后的顺序调用都只能"取下"一次核心，重复调用是空操作；这正是会话重启
// 不再需要整体重建 App（*a.App = App{...}）来重置一次性状态的前提。
func TestAppStopIsConcurrentAndIdempotent(t *testing.T) {
	a := newApp(&config.ClientConfig{}, "")
	a.sess.installCore(&runner.Core{})

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(a.Stop)
	}
	wg.Wait()
	a.Stop() // 顺序重复调用同样安全

	require.Nil(t, a.currentCore())
}

// TestAppStartResetsSessionState 固定"每次 Start 重置会话级状态"：过去这一步由
// 会话重启时的整体重建顺带完成，重建移除后必须由会话起点（session.start）负责，
// 否则上一轮的启动警告会既抑制新一轮的记录（只在 nil 时写入），又被恢复流程
// （restartServiceInSequence）重复上报。
func TestAppStartResetsSessionState(t *testing.T) {
	stubRunCore(t)
	a := newApp(&config.ClientConfig{}, "")
	// 会话级状态是 session 的私有字段：测试在同一把锁下播种。
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

// TestAppStartupWarnAccessIsRaceFree 固定 startupWarn 的读侧契约：它由
// session.start 在会话锁下重置/写入，而自更新失败后的恢复流程
// （restartServiceInSequence）与那次 start 分属不同 goroutine，因此必须走
// currentStartupWarn()。直接读字段会让 -race 报出数据竞争。
func TestAppStartupWarnAccessIsRaceFree(t *testing.T) {
	stubRunCore(t)
	a := newApp(&config.ClientConfig{}, "")

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

// TestUpdateConfigIsRaceFreeAndLossless 固定配置快照的 copy-on-write 契约。
//
// 两个断言各自对应一种失败：
//   - 并发读者（切换/自更新的 Clone 与字段读）与发布不得互相竞争——-race 下失败；
//   - updateConfig 的读改写必须是原子的（CAS 循环），否则两个并发发布者会互相
//     覆盖、丢增量。因此这里让 N 个写者各做 M 次 +1：只有 CAS 才能得到精确的
//     N*M（Load→改→Store 的实现在这条断言下几乎必然小于它）。
//
// 它取代的正是"菜单原地改写 a.cfg"——那既是数据竞争，也会丢失并发更新。
func TestUpdateConfigIsRaceFreeAndLossless(t *testing.T) {
	const writers, perWriter = 4, 200
	a := newApp(&config.ClientConfig{}, "")

	var writersWG sync.WaitGroup
	start := make(chan struct{})
	for range writers {
		writersWG.Go(func() {
			<-start
			for range perWriter {
				a.updateConfig(func(c *config.ClientConfig) { c.Timeout++ })
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
				// 切换/自更新恢复路径的读法：整份快照的克隆，外加字段读。
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

// TestAppStopTakesTheTunManager 固定"Stop 收走当时的 TUN manager"：交给 Stop
// 的 manager 必须被停掉并清空。漏掉它意味着那个引擎的分流路由会留在系统路由
// 表里而无人回收（见 session.tunDown 的注释），这正是本项修复要保住的性质。
func TestAppStopTakesTheTunManager(t *testing.T) {
	a := newApp(&config.ClientConfig{}, "")

	// 零值 manager 的 Stop 是安全的空操作（内部 running 为 false），
	// 不需要真实设备即可验证"取走并停止"这一步。
	a.sess.tunMu.Lock()
	a.sess.tunMgr = &tun.Manager{}
	a.sess.tunMu.Unlock()

	a.Stop()

	a.sess.tunMu.Lock()
	defer a.sess.tunMu.Unlock()
	require.Nil(t, a.sess.tunMgr, "Stop 必须停掉并清空 TUN manager")
}

// TestAppStopAndTunToggleAreRaceFree 固定 tunMgr 的锁契约：托盘的 TUN 开关
// （session.tunUp/tunUpViaHelper/tunDown）与启动期的 startTunEngineAtStartup、
// 停止期的 stop 必须共用 session.tunMu 读写 tunMgr。这里按开关的形状并发执行
// "锁内检查核心、锁内安装 manager"与 App.Stop：任何一方脱离这把锁，-race 都会
// 报出数据竞争。
func TestAppStopAndTunToggleAreRaceFree(t *testing.T) {
	a := newApp(&config.ClientConfig{}, "")

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
