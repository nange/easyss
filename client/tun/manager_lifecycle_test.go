package tun

import (
	"context"
	"errors"
	"testing"
	"time"
)

// managerLifecycleBudget 是"Start/Stop 必须在预算内返回"的上限：把永久挂住变成一次
// 快速失败。
const managerLifecycleBudget = 10 * time.Second

// noopPlatform 返回不触碰设备、路由表与系统 DNS 的平台操作：生命周期测试不需要 root。
func noopPlatform() platform {
	return platform{
		createDev:   func(*Manager) error { return nil },
		closeDev:    func(*Manager) error { return nil },
		saveDNS:     func(*Manager) error { return nil },
		restoreDNS:  func(*Manager) error { return nil },
		engineStart: func() error { return nil },
		engineStop:  func(string) {},
		settle:      func() {},
		ifaceMTU:    func(string) (int, error) { return 1500, nil },
	}
}

// newStubManager 返回使用空平台操作的 Manager，测试再按需覆盖单项。
func newStubManager(cfg Config) *Manager {
	m := New(cfg)
	m.plat = noopPlatform()
	return m
}

func newTestManager() *Manager {
	return newStubManager(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
}

// TestManagerStopWithoutStartDoesNotHang 固定"从未 Start 过的管理器可以安全 Stop"，
// 这是托盘的常态路径：Stop 若依赖"cancel 非 nil ⇒ done 非 nil"，就会在 nil channel
// 上永久阻塞，而托盘是在持有 tunMu 时调用它。
func TestManagerStopWithoutStartDoesNotHang(t *testing.T) {
	t.Parallel()

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

// TestManagerStopWhileStarting 固定"Start 进行中被 Stop 取消"：两者都必须有界返回，
// 且管理器最终不处于运行状态。
func TestManagerStopWhileStarting(t *testing.T) {
	t.Parallel()

	// engineStart 在 Start 发布 ctx/done 之后调用，故这个信号表示"正在进行中"。
	inStart := make(chan struct{}, 1)
	m := newTestManager()
	m.plat.engineStart = func() error {
		select {
		case inStart <- struct{}{}:
		default:
		}
		time.Sleep(2 * time.Millisecond)
		return nil
	}

	startDone := make(chan struct{}, 1)
	go func() {
		_ = m.Start()
		startDone <- struct{}{}
	}()

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

// TestManagerStopIsIdempotent 固定 Stop 的幂等性：关闭脚本与系统 DNS 恢复只能做一次。
func TestManagerStopIsIdempotent(t *testing.T) {
	t.Parallel()

	var engineStops int
	m := newTestManager()
	m.plat.engineStop = func(string) { engineStops++ }
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

// TestManagerStopBeforeStartGoroutineRuns 守住"停止先到、启动后到"：Stop 若按"没有 cancel"
// 当作从未启动返回，Start 随后照常建起引擎与设备，界面说关了、流量还在隧道里，且没人能停它。
func TestManagerStopBeforeStartGoroutineRuns(t *testing.T) {
	t.Parallel()

	var (
		engineStarts int
		creates      int
	)
	m := newTestManager()
	m.plat.engineStart = func() error { engineStarts++; return nil }
	m.plat.createDev = func(*Manager) error { creates++; return nil }

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

// TestManagerStartRunsExactlyOnce 固定"一个 Manager 只承载一次会话"：重复 Start 会
// 覆盖 engine 的包级默认设备（tun2socks 的 Stop 只认全局默认值），让第一套设备与
// 协议栈无人能停，因此必须显式失败。
func TestManagerStartRunsExactlyOnce(t *testing.T) {
	t.Parallel()

	m := newTestManager()
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(m.Stop)

	if err := m.Start(); err == nil {
		t.Fatal("the second Start on the same manager must be rejected")
	}
}

// TestManagerEngineStartFailureReleasesTheDevice 守住 engine 启动失败必须自己释放设备：
// tun2socks 的 engine.Start 先 parseDevice 再 CreateStack，失败路径不清理，而 teardown 也不会调 Stop。
func TestManagerEngineStartFailureReleasesTheDevice(t *testing.T) {
	t.Parallel()

	errStart := errors.New("create stack: permission denied")
	var reasons []string
	m := newTestManager()
	m.plat.engineStart = func() error { return errStart }
	m.plat.engineStop = func(reason string) { reasons = append(reasons, reason) }
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
