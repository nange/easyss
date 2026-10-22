//go:build (darwin || linux) && !headless

package app

import (
	"os"
	"testing"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/stretchr/testify/require"
)

// TestCloseTun2socksVerifiesTheRecordedSession 固定关闭流程的三件事：按启用时
// 记录的会话（而不是关闭时的 manager）核对路由残留、清空所有会话状态、把
// EnableTun2socks 落回 false。
func TestCloseTun2socksVerifiesTheRecordedSession(t *testing.T) {
	session := tun.DeviceConfig{Device: "utun9", TunGW: "198.18.0.1"}
	a := &trayApp{App: New(&clientconfig.ClientConfig{}, "")}
	a.sess.tunSession = &session

	var verified []string
	a.sess.verifyTeardown = func(dev tun.DeviceConfig, owner tun.Owner, signalled bool) error {
		verified = append(verified, dev.Device)
		require.Equal(t, tun.OwnerLocal, owner)
		require.False(t, signalled)
		return nil
	}

	a.sess.tunDown()
	require.Equal(t, []string{"utun9"}, verified)
	require.Nil(t, a.sess.tunSession)
	require.False(t, a.currentConfig().Local.EnableTun2socks)
}

// TestCloseTun2socksSignalsTheHelperFIFO 确认关闭流程仍然通过关闭 FIFO 通知
// helper 退出。
func TestCloseTun2socksSignalsTheHelperFIFO(t *testing.T) {
	a := &trayApp{App: New(&clientconfig.ClientConfig{}, "")}
	a.sess.verifyTeardown = func(tun.DeviceConfig, tun.Owner, bool) error { return nil }

	rd, wr, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() }) //nolint:errcheck
	a.sess.tunHelperStdin = wr

	a.sess.tunDown()
	require.Nil(t, a.sess.tunHelperStdin, "关闭后必须清空 helper 的 FIFO 写端")

	_, err = wr.Write([]byte("x"))
	require.Error(t, err, "FIFO 写端必须已经关闭，helper 才能从 stdin 读到 EOF")
}
