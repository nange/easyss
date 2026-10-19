package tun

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// teardownRecorder 记录一次 teardown 真正执行了哪些清理动作。
//
// 它是 (reason × owner) 矩阵的观测点：矩阵断言的是"做了什么"，而不是
// 代码里怎么判断的——这正是把 fdMode / SkipRouteCleanup / helperSignalled
// 三套隐式条件换成显式所有权之后需要锁住的东西。
type teardownRecorder struct {
	engineStops  []string
	closeScripts int
	dnsRestores  int
}

// stubTeardownHooks 把会触碰真实设备与系统 DNS 的钩子换成记录器。它是
// stubManagerHooks 的"可观测"版本：后者只保证测试不碰系统，这个版本还要
// 能回答"哪一步跑了、跑了几次"。
func stubTeardownHooks(t *testing.T) *teardownRecorder {
	t.Helper()

	rec := &teardownRecorder{}

	createDev, closeDev := createTunDevFn, closeTunDevFn
	saveDNS, restoreDNS := saveAndSetDNSStepFn, restoreDNSStepFn
	startEngine, stopEngineHook := engineStartFn, engineStopFn
	settle := settleDelay
	t.Cleanup(func() {
		createTunDevFn, closeTunDevFn = createDev, closeDev
		saveAndSetDNSStepFn, restoreDNSStepFn = saveDNS, restoreDNS
		engineStartFn, engineStopFn = startEngine, stopEngineHook
		settleDelay = settle
	})

	createTunDevFn = func(*Manager) error { return nil }
	closeTunDevFn = func(*Manager) error {
		rec.closeScripts++
		return nil
	}
	saveAndSetDNSStepFn = func(m *Manager) error {
		// 与真实实现一致：只有真的改过系统 DNS 时 dnsChanged 才为 true，
		// 而 teardown 只恢复"改过"的那一次。
		m.originDNS = []string{"192.168.1.1"}
		m.dnsChanged = true
		return nil
	}
	restoreDNSStepFn = func(*Manager) error {
		rec.dnsRestores++
		return nil
	}
	engineStartFn = func() error { return nil }
	engineStopFn = func(reason string) { rec.engineStops = append(rec.engineStops, reason) }
	settleDelay = func() {}

	return rec
}

// TestTeardownMatrix 固定 (owner × 已建立步骤) → 执行哪些清理 的完整矩阵。
//
// 三套旧条件的每一种组合都在这里：直连路径必须跑关闭脚本并恢复 DNS；
// helper 路径必须只停引擎（路由与 DNS 归 helper，主进程去跑只会与它抢）；
// 创建脚本失败时路由可能已经装上了，因此关闭脚本必须跑；还没碰过系统就
// 失败时什么都不该做。
func TestTeardownMatrix(t *testing.T) {
	if !manageSystemDNS() {
		t.Skip("this platform does not switch the system DNS for TUN")
	}

	cases := []struct {
		name          string
		owner         Owner
		engineUp      bool
		deviceUp      bool
		dnsTouched    bool
		wantEngine    bool
		wantClose     int
		wantDNSRestor int
	}{
		{
			name:        "local: engine, device and dns are all ours",
			owner:       OwnerLocal,
			engineUp: true, deviceUp: true, dnsTouched: true,
			wantEngine:  true, wantClose: 1, wantDNSRestor: 1,
		},
		{
			name:        "local: create script never ran",
			owner:       OwnerLocal,
			engineUp: true,
			wantEngine:  true, wantClose: 0, wantDNSRestor: 0,
		},
		{
			name:        "local: create script failed halfway, routes may exist",
			owner:       OwnerLocal,
			engineUp: true, deviceUp: true,
			wantEngine:  true, wantClose: 1, wantDNSRestor: 0,
		},
		{
			name:        "helper: engine only, routes and dns belong to the helper",
			owner:       OwnerHelper,
			engineUp: true, deviceUp: true, dnsTouched: true,
			wantEngine:  true, wantClose: 0, wantDNSRestor: 0,
		},
		{
			name:        "helper: nothing but the engine came up",
			owner:       OwnerHelper,
			engineUp: true,
			wantEngine:  true, wantClose: 0, wantDNSRestor: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := stubTeardownHooks(t)

			m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
			m.owner = tc.owner
			m.engineUp = tc.engineUp
			m.deviceUp = tc.deviceUp
			m.dnsTouched = tc.dnsTouched
			if tc.dnsTouched {
				m.dnsChanged = true
			}

			require.NoError(t, m.teardown(ReasonStop, tc.owner))

			require.Equal(t, tc.wantEngine, len(rec.engineStops) == 1,
				"engine.Stop 必须恰好跑一次（它是释放 fd 的那一步）")
			require.Equal(t, tc.wantClose, rec.closeScripts,
				"只有本进程装的设备才需要跑关闭脚本")
			require.Equal(t, tc.wantDNSRestor, rec.dnsRestores,
				"只有本进程改过的系统 DNS 才需要恢复")
		})
	}
}

// TestTeardownRunsOnce 固定"一次会话只拆一次"：Stop 与 Start 的失败路径可能
// 先后到达 teardown（Stop 等在 done 上，Start 的 defer 也走拆除），而关脚本与
// 恢复 DNS 都是只能做一次的动作——重复跑会让第二次的失败被记成用户可见的错误。
func TestTeardownRunsOnce(t *testing.T) {
	rec := stubTeardownHooks(t)

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
	m.owner = OwnerLocal
	m.engineUp, m.deviceUp, m.dnsTouched, m.dnsChanged = true, true, true, true

	require.NoError(t, m.teardown(ReasonStartFailed, OwnerLocal))
	require.NoError(t, m.teardown(ReasonStop, OwnerLocal))

	require.Equal(t, 1, len(rec.engineStops), "engine must be stopped exactly once")
	require.Equal(t, 1, rec.closeScripts, "the close script must run exactly once")
	if manageSystemDNS() {
		require.Equal(t, 1, rec.dnsRestores, "the system dns must be restored exactly once")
	}
}

// TestTeardownReportsCleanupFailures 固定"清理失败会被上报，但不改变拆除结果"：
// 调用方已经处在拆除路径上，关闭脚本失败唯一能做的就是让调用方知道（它的日志
// 与通知是第一手证据），绝不能让它误以为整次拆除失败了。
func TestTeardownReportsCleanupFailures(t *testing.T) {
	rec := stubTeardownHooks(t)
	errBoom := errors.New("route: permission denied")
	closeTunDevFn = func(*Manager) error { return errBoom }

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
	m.owner = OwnerLocal
	m.engineUp, m.deviceUp = true, true

	err := m.teardown(ReasonCreateFailed, OwnerLocal)
	require.ErrorIs(t, err, errBoom, "the cleanup failure must reach the caller")
	require.Equal(t, 1, len(rec.engineStops), "the engine still has to be stopped")
}

// TestStopIsANoOpOnAFreshManager 固定"从未 Start 过的管理器可以安全 Stop"，
// 并且这一次确实什么都不做：没有引擎要停、没有关闭脚本要跑（跑它会去提权，
// 还可能删掉别的会话的路由）。
func TestStopIsANoOpOnAFreshManager(t *testing.T) {
	rec := stubTeardownHooks(t)

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
	m.Stop()

	require.Zero(t, len(rec.engineStops), "a manager that never started has no engine to stop")
	require.Zero(t, rec.closeScripts, "a manager that never started has no routes to delete")
	require.Zero(t, rec.dnsRestores, "a manager that never started never touched the system dns")
}

// TestStopTearsDownAHalfStartedSession 固定另一半：Start 半途失败之后 Stop 仍然
// 能把残局收干净。它过去靠 m.running 提前返回，于是创建脚本装上的路由没人删。
func TestStopTearsDownAHalfStartedSession(t *testing.T) {
	rec := stubTeardownHooks(t)

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
	m.engineUp = true
	m.deviceUp = true
	m.dnsTouched = true
	m.dnsChanged = true

	m.Stop()

	require.Equal(t, 1, len(rec.engineStops), "引擎必须停")
	require.Equal(t, 1, rec.closeScripts, "半途失败装上的路由必须被删掉")
	if manageSystemDNS() {
		require.Equal(t, 1, rec.dnsRestores, "半途失败改过的系统 DNS 必须恢复")
	}
}
