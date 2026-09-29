package tun

import (
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
