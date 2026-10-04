package main

import (
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
)

// stubAppUI 是 appUI 的测试替身：记录主程序呈现给界面的状态。它取代了过去那四个
// 包级函数变量（tunStartFailureHook/tunStartNotify/tunStartErrorText/
// serverDomainReadyNotify），因此测试不再需要全局替换与逐个还原。
//
// 通道都带缓冲：生产代码在引擎 goroutine 上调用它，测试不读时也不能阻塞。
type stubAppUI struct {
	tunFailures chan error
	notices     chan string
	domainReady chan string
}

func newStubAppUI() *stubAppUI {
	return &stubAppUI{
		tunFailures: make(chan error, 8),
		notices:     make(chan string, 8),
		domainReady: make(chan string, 8),
	}
}

func (s *stubAppUI) tunStartFailed(err error)     { s.tunFailures <- err }
func (s *stubAppUI) notify(msg string)            { s.notices <- msg }
func (s *stubAppUI) serverDomainReady(msg string) { s.domainReady <- msg }

// fakeDomainReadiness 是 serverDomainReadiness 的测试替身：cmd 包内无法构造
// 带可用通道的 *runner.Core（字段不可导出）。
type fakeDomainReadiness struct {
	ready <-chan struct{}
	done  <-chan struct{}
}

func (f fakeDomainReadiness) ServerDomainReady() <-chan struct{} { return f.ready }
func (f fakeDomainReadiness) Done() <-chan struct{}              { return f.done }

// failedTunManager 构建一个 Start() 会立即失败的 manager，这样无需 root、
// 也无需接触真实的 TUN 设备即可测试引擎失败路径：不可解析的日志级别会被
// 引擎的 general() 步骤拒绝，此时尚未打开任何设备。
func failedTunManager() *tun.Manager {
	return tun.New(tun.Config{LogLevel: "not-a-log-level"})
}

// TestStartTunEngineReportsFailureToUI 固定界面所依赖的契约：引擎启动失败必须
// 到达 appUI.tunStartFailed —— 托盘据此复原菜单项并拆除提权 helper。否则菜单会
// 一直声称 TUN 已开启，而实际上没有任何流量经过它。
func TestStartTunEngineReportsFailureToUI(t *testing.T) {
	a := newApp(&config.ClientConfig{}, "")
	ui := newStubAppUI()
	a.ui = ui

	a.sess.startTunEngine(failedTunManager(), "device")

	select {
	case err := <-ui.tunFailures:
		if err == nil {
			t.Fatal("a nil error was reported as a TUN start failure")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("appUI.tunStartFailed was not called after the engine failed to start")
	}
}

// TestNotifyWithoutUIIsLogOnly 固定 headless 与 --disable-tray 构建的行为：
// App.ui 为 nil（没有界面）时，通知与"网络已恢复"的观察都只写日志，不 panic、
// 也不派发任何东西。这些入口过去靠"钩子为 nil"隐式短路，现在是显式的 nil 检查。
func TestNotifyWithoutUIIsLogOnly(t *testing.T) {
	a := &App{} // 没有界面，也没有会话：这些入口都不该依赖会话状态
	if a.ui != nil {
		t.Fatal("a bare App must have no UI")
	}

	a.notifyTunSkipped("tun skipped")
	a.notifyTunSkippedNoRoot()
	a.notifyTunSkippedNetworkUnready()
	a.notifyTunTeardownProblem("leftover routes")

	// 降级启动的通知观察者在没有界面时不得派发 goroutine。
	ready := make(chan struct{})
	a.watchServerDomainReady(fakeDomainReadiness{ready: ready}, coreGen.Add(1), true, true)

	select {
	case <-ready:
		t.Fatal("watchServerDomainReady must not consume the readiness channel without a UI")
	case <-time.After(50 * time.Millisecond):
	}
	close(ready)
}
