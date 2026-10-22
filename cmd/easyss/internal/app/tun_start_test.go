package app

import (
	"errors"
	"testing"
	"time"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/stretchr/testify/require"
)

// stubAppUI 是 appUI 的测试替身：通道都带缓冲，因为生产代码在引擎 goroutine 上
// 调用它，测试不读时也不能阻塞。
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
func (s *stubAppUI) browserProxyEnabled() bool    { return false }
func (s *stubAppUI) setTunMenuChecked(bool)       {}

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

// stubPlatformTeardown 把"等 helper 退出 + 复核系统路由表"这一步换成空实现：
// 真实实现会读运行测试的机器的路由表，必要时还会执行平台脚本去删路由。
func stubPlatformTeardown(s *session) {
	s.verifyTeardown = func(tun.DeviceConfig, tun.Owner, bool) error { return nil }
}

// TestStartTunEngineReportsFailureToUI 守住两个后果：失败必须到达 appUI.tunStartFailed，
// 且半启用的会话必须被拆掉，否则下次启用会命中"已设置"保护、静默什么都不做。
func TestStartTunEngineReportsFailureToUI(t *testing.T) {
	a := New(&clientconfig.ClientConfig{}, "")
	ui := newStubAppUI()
	a.ui = ui
	stubPlatformTeardown(a.sess)

	// 失败回调只回滚它自己那次会话（见 rollbackFailedTunStart），因此这里先把
	// 这次启动登记为当前会话——生产路径的 tunUp/tunUpViaHelper/
	// startTunEngineAtStartup 都是这么做的。
	mgr := failedTunManager()
	a.sess.tunMu.Lock()
	a.sess.tunMgr = mgr
	a.sess.tunMu.Unlock()

	a.sess.startTunEngine(mgr, "device")

	select {
	case err := <-ui.tunFailures:
		if err == nil {
			t.Fatal("a nil error was reported as a TUN start failure")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("appUI.tunStartFailed was not called after the engine failed to start")
	}

	a.sess.tunMu.Lock()
	remaining := a.sess.tunMgr
	a.sess.tunMu.Unlock()
	require.Nil(t, remaining, "失败的会话必须被拆掉，下次启用才能装上新引擎")
}

// TestStaleTunStartFailureLeavesTheCurrentSessionAlone 守住迟到的失败回调只回滚它
// 自己那次会话：这期间用户可能已重新开启 TUN，拆错会话连提示都没有。
func TestStaleTunStartFailureLeavesTheCurrentSessionAlone(t *testing.T) {
	a := New(&clientconfig.ClientConfig{}, "")
	ui := newStubAppUI()
	a.ui = ui
	stubPlatformTeardown(a.sess)

	a.updateConfig(func(c *clientconfig.ClientConfig) { c.Local.EnableTun2socks = true })
	stale, current := failedTunManager(), failedTunManager()
	a.sess.tunMu.Lock()
	a.sess.tunMgr = current
	a.sess.tunMu.Unlock()

	a.sess.rollbackFailedTunStart(stale, errors.New("tun: start cancelled while the user re-enabled it"))

	a.sess.tunMu.Lock()
	got := a.sess.tunMgr
	a.sess.tunMu.Unlock()
	require.Same(t, current, got, "迟到的失败回调不得拆掉新会话")
	require.True(t, a.currentConfig().Local.EnableTun2socks, "新会话的启用偏好不得被清掉")
	select {
	case err := <-ui.tunFailures:
		t.Fatalf("a stale failure must not reach the UI, got %v", err)
	default:
	}
}

// TestTunStartFailureRollsBackOnlyItsOwnSession 是上一条的正向分支：属于当前会话的
// 失败必须被拆除、偏好必须落回 false、界面必须收到原因。
func TestTunStartFailureRollsBackOnlyItsOwnSession(t *testing.T) {
	a := New(&clientconfig.ClientConfig{}, "")
	ui := newStubAppUI()
	a.ui = ui
	stubPlatformTeardown(a.sess)

	a.updateConfig(func(c *clientconfig.ClientConfig) { c.Local.EnableTun2socks = true })
	mgr := failedTunManager()
	a.sess.tunMu.Lock()
	a.sess.tunMgr = mgr
	a.sess.tunSession = &tun.DeviceConfig{Device: "utun-test"}
	a.sess.tunMu.Unlock()

	errBoom := errors.New("tun: create device: boom")
	a.sess.rollbackFailedTunStart(mgr, errBoom)

	a.sess.tunMu.Lock()
	remaining, dev := a.sess.tunMgr, a.sess.tunSession
	a.sess.tunMu.Unlock()
	require.Nil(t, remaining, "失败的会话必须被拆掉")
	require.Nil(t, dev, "会话的设备配置必须被清空")
	require.False(t, a.currentConfig().Local.EnableTun2socks, "启用偏好必须落回 false")

	select {
	case got := <-ui.tunFailures:
		require.ErrorIs(t, got, errBoom)
	default:
		t.Fatal("the UI was not told about the failed start")
	}
}

// TestNotifyWithoutUIIsLogOnly 固定 headless 与 --disable-tray 构建的行为：
// App.ui 为 nil（没有界面）时，通知与"网络已恢复"的观察都只写日志，不 panic、
// 也不派发任何东西。这些入口必须显式判 nil，不能靠"钩子为 nil"隐式短路。
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
