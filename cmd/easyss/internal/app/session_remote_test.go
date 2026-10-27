package app

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/runner"
	"github.com/stretchr/testify/require"
)

type fakeRemoteHelper struct {
	control io.WriteCloser
	waited  chan struct{}
	done    chan struct{}
	once    sync.Once
	waitErr error
}

func (f *fakeRemoteHelper) Control() io.WriteCloser { return f.control }

func (f *fakeRemoteHelper) Done() <-chan struct{} { return f.done }

func (f *fakeRemoteHelper) Err() error { return f.waitErr }

func (f *fakeRemoteHelper) Wait(time.Duration) error {
	f.exit()
	return f.waitErr
}

// exit 模拟 helper 进程退出：正常拆除由 Wait 触发，外部结束（被杀/崩溃）直接调它。
func (f *fakeRemoteHelper) exit() {
	f.once.Do(func() {
		close(f.waited)
		close(f.done)
	})
}

func newRemoteTestSession(t *testing.T) (*App, *runner.Core, *fakeRemoteHelper, tun.DeviceConfig) {
	t.Helper()

	core := &runner.Core{Client: &client.Client{}}
	a := New(&clientconfig.ClientConfig{}, "")
	a.sess.installCore(core)
	a.sess.verifyTeardown = func(tun.DeviceConfig, tun.Owner, bool) error { return nil }

	_, w := io.Pipe()
	h := &fakeRemoteHelper{control: w, waited: make(chan struct{}), done: make(chan struct{})}
	dev := tun.DeviceConfig{Device: "easyss", TunGW: "198.18.0.1"}
	return a, core, h, dev
}

// TestRemoteTunLifecycle 固定 Windows helper 路径的状态机：spawn 前就必须发布 TUN mode
// （helper 会在 READY 前装路由），READY 后才放行 forward DNS；拆除时先关控制连接、再等
// helper 退出，最后才解绑拨号器。
func TestRemoteTunLifecycle(t *testing.T) {
	a, core, h, dev := newRemoteTestSession(t)

	a.sess.tunMu.Lock()
	a.sess.beginRemoteTun(dev)
	require.True(t, core.Client.TunModeEnabled(), "spawn 前就要绑定物理接口")
	require.False(t, core.Client.TunForwardingEnabled(), "helper 未 READY 前 forward DNS 必须拒答")

	a.sess.adoptRemoteTun(h)
	require.True(t, core.Client.TunForwardingEnabled())
	a.sess.tunMu.Unlock()

	require.True(t, a.currentConfig().Local.EnableTun2socks)

	a.sess.tunDown()

	select {
	case <-h.waited:
	default:
		t.Fatal("tunDown 必须先等 helper 清理完再复核路由")
	}
	require.False(t, core.Client.TunModeEnabled())
	require.False(t, core.Client.TunForwardingEnabled())
	require.False(t, a.currentConfig().Local.EnableTun2socks)
}

func TestCancelRemoteTunRollsBackPendingState(t *testing.T) {
	a, core, _, dev := newRemoteTestSession(t)

	a.sess.tunMu.Lock()
	a.sess.beginRemoteTun(dev)
	a.sess.cancelRemoteTun()
	a.sess.tunMu.Unlock()

	require.False(t, core.Client.TunModeEnabled())
	require.False(t, core.Client.TunForwardingEnabled())
	require.False(t, a.currentConfig().Local.EnableTun2socks)
}

// TestRemoteHelperExitRollsBackTunState 守住 helper 非主动退出：适配器与分流路由随进程
// 消失，主进程必须撤销 TUN 状态并取消托盘勾选，否则界面说全局流量开着、实际已直连。
func TestRemoteHelperExitRollsBackTunState(t *testing.T) {
	a, core, h, dev := newRemoteTestSession(t)

	a.sess.tunMu.Lock()
	a.sess.beginRemoteTun(dev)
	a.sess.adoptRemoteTun(h)
	a.sess.tunMu.Unlock()

	h.waitErr = errors.New("exit code 1")
	h.exit()

	require.Eventually(t, func() bool {
		a.sess.tunMu.Lock()
		defer a.sess.tunMu.Unlock()
		return !a.sess.tunRemote && !a.sess.tunActive
	}, 2*time.Second, 10*time.Millisecond)

	require.False(t, core.Client.TunModeEnabled())
	require.False(t, core.Client.TunForwardingEnabled())
	require.False(t, a.currentConfig().Local.EnableTun2socks)
}
