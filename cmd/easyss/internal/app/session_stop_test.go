package app

import (
	"io"
	"os"
	"testing"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/stretchr/testify/require"
)

// TestStopReclaimsTunInstalledAfterTunDown 固定 App.Stop 的两段式拆除：托盘 tunUp 可以
// 在 tunDown 与 stop 之间拿到 tunMu，因此 stop 必须做完整拆除而不是只停引擎——否则
// helper 的 FIFO 不会被关闭，它会继续持 flock、路由与系统 DNS。
func TestStopReclaimsTunInstalledAfterTunDown(t *testing.T) {
	a := New(&clientconfig.ClientConfig{}, "")
	var verified []tun.Owner
	a.sess.verifyTeardown = func(_ tun.DeviceConfig, owner tun.Owner, signalled bool) error {
		verified = append(verified, owner)
		require.True(t, signalled, "helper 会话必须先关 FIFO 再核对拆除")
		return nil
	}

	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { pr.Close() }) //nolint:errcheck

	a.sess.tunMu.Lock()
	a.sess.tunMgr = failedTunManager()
	a.sess.tunSession = &tun.DeviceConfig{Device: "utun9", TunGW: "198.18.0.1"}
	a.sess.tunOwner = tun.OwnerHelper
	a.sess.tunHelperStdin = pw
	a.sess.tunMu.Unlock()
	a.updateConfig(func(c *clientconfig.ClientConfig) { c.Local.EnableTun2socks = true })

	a.sess.stop()

	a.sess.tunMu.Lock()
	mgr, dev, owner, stdin := a.sess.tunMgr, a.sess.tunSession, a.sess.tunOwner, a.sess.tunHelperStdin
	a.sess.tunMu.Unlock()

	require.Nil(t, mgr, "stop 之后不得留下无人持有的引擎")
	require.Nil(t, dev, "stop 必须清空启用时记录的设备配置")
	require.Equal(t, tun.OwnerLocal, owner, "stop 之后所有权必须回到默认值")
	require.Nil(t, stdin, "stop 必须关闭并清空 helper 的 FIFO")
	require.Equal(t, []tun.Owner{tun.OwnerHelper}, verified, "拆除必须复核 helper 会话的路由")
	require.False(t, a.currentConfig().Local.EnableTun2socks, "启用偏好必须落回 false")

	// FIFO 写端已经关闭时，helper 才能从 stdin 读到 EOF 并自己清理。
	_, err = pw.Write([]byte("x"))
	require.Error(t, err)
	_, err = pr.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}
