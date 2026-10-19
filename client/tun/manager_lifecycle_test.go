package tun

import (
	"context"
	"errors"
	"testing"
	"time"
)

// managerLifecycleBudget 是"Start/Stop 必须在预算内返回"的上限：把"永久挂住"
// 变成一次快速失败。正常路径远小于该值。
const managerLifecycleBudget = 10 * time.Second

// stubManagerHooks 把会触碰真实 TUN 设备、路由表与系统 DNS 的 hook 全部替换为
// 空实现：管理器的生命周期测试不需要 root，也不能改写运行测试的机器的网络配置。
func stubManagerHooks(t *testing.T) {
	t.Helper()

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
	closeTunDevFn = func(*Manager) error { return nil }
	saveAndSetDNSStepFn = func(*Manager) error { return nil }
	restoreDNSStepFn = func(*Manager) error { return nil }
	engineStartFn = func() error { return nil }
	engineStopFn = func(string) {}
	settleDelay = func() {}
}

func newTestManager() *Manager {
	return New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
}

// TestManagerStopWithoutStartDoesNotHang 固定"从未 Start 过的管理器可以安全
// Stop"。这是托盘的常态路径：用户从未开启过 TUN 就退出/切换服务器。
//
// 旧形态下 Stop 依赖"cancel 非 nil ⇒ done 非 nil"这一未受保护的假设，两者
// 分两步发布时 Stop 会在 nil channel 上永久阻塞；而托盘调用 Stop 时持有
// tunHelperMu，卡住的是整个菜单。
func TestManagerStopWithoutStartDoesNotHang(t *testing.T) {
	stubManagerHooks(t)
	m := newTestManager()

	done := make(chan struct{})
	go func() {
		m.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(managerLifecycleBudget):
		t.Fatal("Stop on a never-started manager blocked forever")
	}

	if m.IsRunning() {
		t.Fatal("IsRunning must be false on a never-started manager")
	}
}

// TestManagerStopWhileStarting 固定"Start 进行中被 Stop 取消"这一并发路径：
// Start 在后台 goroutine 上运行（startTunEngine），Stop 可以来自托盘或退出
// 路径。两者都必须有界返回，且管理器最终不处于运行状态。
func TestManagerStopWhileStarting(t *testing.T) {
	stubManagerHooks(t)

	// engineStartFn 在 Start 发布 ctx/done 之后被调用，因此这个信号可靠地
	// 表示"Start 正在进行中"（而不是还没开始）。
	inStart := make(chan struct{}, 1)
	engineStartFn = func() error {
		select {
		case inStart <- struct{}{}:
		default:
		}
		time.Sleep(2 * time.Millisecond)
		return nil
	}

	m := newTestManager()

	startDone := make(chan error, 1)
	go func() { startDone <- m.Start() }()

	select {
	case <-inStart:
	case <-time.After(managerLifecycleBudget):
		t.Fatal("Start never reached the engine start step")
	}

	stopDone := make(chan struct{})
	go func() {
		m.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
	case <-time.After(managerLifecycleBudget):
		t.Fatal("Stop blocked while Start was in flight")
	}

	select {
	case <-startDone:
	case <-time.After(managerLifecycleBudget):
		t.Fatal("Start did not return after Stop cancelled it")
	}

	if m.IsRunning() {
		t.Fatal("manager still reports running after Stop")
	}
}

// TestManagerStopIsIdempotent 固定 Stop 的幂等性：关闭脚本与系统 DNS 恢复
// 都是"只能做一次"的动作，重复 Stop 不得再执行一遍。
func TestManagerStopIsIdempotent(t *testing.T) {
	stubManagerHooks(t)

	var engineStops int
	engineStopFn = func(string) { engineStops++ }

	m := newTestManager()
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !m.IsRunning() {
		t.Fatal("manager must report running after a successful Start")
	}

	m.Stop()
	m.Stop()

	if m.IsRunning() {
		t.Fatal("manager still reports running after Stop")
	}
	if engineStops != 1 {
		t.Fatalf("engine stopped %d times, want exactly 1", engineStops)
	}
}

// TestManagerStopBeforeStartGoroutineRuns 固定"停止先到、启动后到"这一时序。
//
// session.tunUp / tunUpViaHelper 在 tunMu 内发布 manager 之后才派发 goroutine
// 去调用 Start（见 cmd/easyss 的 startTunEngine），用户的下一次点击完全可以落在
// 那个 goroutine 被调度之前。此时 Stop 若只按"有没有 cancel"判断，就会当作
// "从未启动"直接返回，而 Start 随后照常把引擎、设备、路由与系统 DNS 全部建立
// 起来：session 那边已经把这个 manager 收走并发布了 EnableTun2socks=false，
// 于是界面说"已关闭"、流量却仍在隧道里，而且再没有人持有这个 manager 去停它。
// 下一次点击会新建一套，engine 的包级默认设备被覆盖，前一套永远停不掉。
//
// 因此：Stop 之后再 Start 必须失败，且不得留下任何系统改动。
func TestManagerStopBeforeStartGoroutineRuns(t *testing.T) {
	stubManagerHooks(t)

	var (
		engineStarts int
		creates      int
	)
	engineStartFn = func() error { engineStarts++; return nil }
	createTunDevFn = func(*Manager) error { creates++; return nil }

	m := newTestManager()

	// 模拟"goroutine 还没被调度到"：Stop 先执行，Start 之后才进入。
	m.Stop()

	err := m.Start()
	if err == nil {
		t.Fatal("Start succeeded after Stop: the session layer already dropped this manager")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Start after Stop = %v, want context.Canceled", err)
	}
	if m.IsRunning() {
		t.Fatal("manager reports running after a Stop that arrived first")
	}
	if engineStarts != 0 {
		t.Fatalf("engine started %d times: a cancelled start must not touch the system", engineStarts)
	}
	if creates != 0 {
		t.Fatalf("create script ran %d times: a cancelled start must not touch the network config", creates)
	}
}

// TestManagerStartRunsExactlyOnce 固定"一个 Manager 只承载一次会话"。重复 Start
// 过去会覆盖 engine 的包级默认设备（tun2socks 的 Stop 只认全局默认值），让第一套
// 设备与协议栈无人能停；现在它必须显式失败。
func TestManagerStartRunsExactlyOnce(t *testing.T) {
	stubManagerHooks(t)

	m := newTestManager()
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(m.Stop)

	if err := m.Start(); err == nil {
		t.Fatal("the second Start on the same manager must be rejected")
	}
}

// TestManagerEngineStartFailureReleasesTheDevice 固定"engine 启动失败必须自己
// 释放设备"。
//
// tun2socks 的 engine.Start 先 parseDevice（打开 TUN 设备 / 包装 helper 传来的
// fd）再 core.CreateStack，而它的失败路径不会清理已打开的设备（tun2socks
// #550/#552）。此时 engineUp 尚未置位，teardown 不会替我们调 engine.Stop，
// 因此 Start 必须在返回错误前显式释放：否则设备（fd 路径上是 helper 传来的
// fd）会泄漏到下一次启用，Linux 上设备还会随这个 fd 一直存活。
func TestManagerEngineStartFailureReleasesTheDevice(t *testing.T) {
	stubManagerHooks(t)

	errStart := errors.New("create stack: permission denied")
	var reasons []string
	engineStartFn = func() error { return errStart }
	engineStopFn = func(reason string) { reasons = append(reasons, reason) }

	m := newTestManager()
	err := m.Start()
	if !errors.Is(err, errStart) {
		t.Fatalf("Start = %v, want the engine error", err)
	}
	if len(reasons) != 1 {
		t.Fatalf("engine stopped %d times, want exactly 1: the device opened before CreateStack failed must be released", len(reasons))
	}
	if m.IsRunning() {
		t.Fatal("manager reports running after a failed engine start")
	}

	// 清理已在 Start 的失败路径里做过，之后的 Stop 不得再停一次。
	m.Stop()
	if len(reasons) != 1 {
		t.Fatalf("engine stopped %d times after Stop, want still 1", len(reasons))
	}
}
