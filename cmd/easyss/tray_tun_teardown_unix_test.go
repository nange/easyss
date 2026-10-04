//go:build (darwin || linux) && !headless

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/util"
	"github.com/stretchr/testify/require"
)

// stubTunTeardownHooks 用可控的探测/回滚替换真实实现，并在测试结束后还原。
// 真实实现要 root 才能造出残留路由，也会改写运行测试的机器的路由表。
func stubTunTeardownHooks(t *testing.T) {
	t.Helper()

	origProbe, origRollback, origLock := tunRouteResidue, rollbackTunRoutes, tunControlLockPath
	t.Cleanup(func() {
		tunRouteResidue, rollbackTunRoutes, tunControlLockPath = origProbe, origRollback, origLock
	})
	tunControlLockPath = filepath.Join(t.TempDir(), "easyss-tun.lock")
}

// TestWaitTunHelperExit 固定"父进程如何判断提权 helper 是否已经退出"：helper 由
// osascript/pkexec 后台拉起（PPID 为 1），父进程拿不到它的 pid，唯一可靠的信号是
// 它持有的文件锁——内核会在进程退出时释放它，被 kill -9 也一样。
func TestWaitTunHelperExit(t *testing.T) {
	stubTunTeardownHooks(t)

	t.Run("no lock file yet", func(t *testing.T) {
		require.NoError(t, waitTunHelperExit(50*time.Millisecond),
			"从未启动过 helper 时不该等待或报错")
	})

	holder, err := os.OpenFile(tunControlLockPath, os.O_CREATE|os.O_RDWR, 0o644)
	require.NoError(t, err)
	t.Cleanup(func() { holder.Close() }) //nolint:errcheck

	require.NoError(t, util.FlockWait(holder, time.Second), "模拟仍活着的 helper")

	err = waitTunHelperExit(100 * time.Millisecond)
	require.Error(t, err, "仍持有锁的 helper 必须被识别为还活着")
	require.Contains(t, err.Error(), "still holds")

	require.NoError(t, util.Unflock(holder))
	require.NoError(t, waitTunHelperExit(time.Second), "helper 退出后必须立刻放行")
}

// TestVerifyTunTeardown 覆盖拆除后的复核：只要探测到 TUN 路由残留就提权回滚，
// 回滚仍失败则把问题报给调用方（由它通知用户），绝不让"路由还在、流量黑洞"
// 静默通过。
func TestVerifyTunTeardown(t *testing.T) {
	stubTunTeardownHooks(t)

	dev := tun.DeviceConfig{Device: "utun9", TunGW: "198.18.0.1"}

	t.Run("clean teardown does not roll back", func(t *testing.T) {
		rollbacks := 0
		tunRouteResidue = func(string, string) (string, bool) { return "", false }
		rollbackTunRoutes = func(tun.DeviceConfig) error {
			rollbacks++
			return nil
		}

		require.NoError(t, verifyTunTeardown(dev))
		require.Zero(t, rollbacks)
	})

	t.Run("leftover routes are rolled back and re-checked", func(t *testing.T) {
		probes, rollbacks := 0, 0
		var gotDevice, gotGateway string
		tunRouteResidue = func(device, tunGW string) (string, bool) {
			probes++
			gotDevice, gotGateway = device, tunGW
			return "gateway: 198.18.0.1", probes == 1 // 回滚之后探测干净了
		}
		rollbackTunRoutes = func(tun.DeviceConfig) error {
			rollbacks++
			return nil
		}

		require.NoError(t, verifyTunTeardown(dev))
		require.Equal(t, 1, rollbacks)
		require.Equal(t, 2, probes, "回滚之后必须重新探测一次")
		require.Equal(t, "utun9", gotDevice)
		require.Equal(t, "198.18.0.1", gotGateway)
	})

	t.Run("rollback failure is reported", func(t *testing.T) {
		errBoom := errors.New("no privilege")
		tunRouteResidue = func(string, string) (string, bool) { return "gateway: 198.18.0.1", true }
		rollbackTunRoutes = func(tun.DeviceConfig) error { return errBoom }

		err := verifyTunTeardown(dev)
		require.ErrorIs(t, err, errBoom)
	})

	t.Run("residue after rollback is reported", func(t *testing.T) {
		rollbacks := 0
		tunRouteResidue = func(string, string) (string, bool) { return "gateway: 198.18.0.1", true }
		rollbackTunRoutes = func(tun.DeviceConfig) error {
			rollbacks++
			return nil
		}

		err := verifyTunTeardown(dev)
		require.Error(t, err)
		require.Contains(t, err.Error(), "仍然残留")
		require.Equal(t, 1, rollbacks)
	})
}

// TestTunDownVerifiesTheRecordedSession 固定关闭流程的三件事：按启用时
// 记录的会话（而不是关闭时的 manager）核对路由残留、清空所有会话状态、把
// EnableTun2socks 落回 false。
func TestCloseTun2socksVerifiesTheRecordedSession(t *testing.T) {
	stubTunTeardownHooks(t)

	session := tun.DeviceConfig{Device: "utun9", TunGW: "198.18.0.1"}
	a := &TrayApp{App: newApp(&config.ClientConfig{}, "")}
	a.sess.tunSession = &session

	var probed []string
	tunRouteResidue = func(device, _ string) (string, bool) {
		probed = append(probed, device)
		return "", false
	}
	rollbackTunRoutes = func(tun.DeviceConfig) error {
		t.Fatal("干净的拆除不该触发回滚")
		return nil
	}

	require.NoError(t, a.sess.tunDown())
	require.Equal(t, []string{"utun9"}, probed)
	require.Nil(t, a.sess.tunSession)
	require.False(t, a.currentConfig().Local.EnableTun2socks)
}

// TestTunDownSignalsTheHelperFIFO 确认关闭流程仍然通过关闭 FIFO 通知
// helper 退出，并且会等它释放控制锁（这里锁是空闲的，因此立即返回）。
func TestCloseTun2socksSignalsTheHelperFIFO(t *testing.T) {
	stubTunTeardownHooks(t)

	a := &TrayApp{App: newApp(&config.ClientConfig{}, "")}
	tunRouteResidue = func(string, string) (string, bool) { return "", false }
	rollbackTunRoutes = func(tun.DeviceConfig) error { return nil }

	rd, wr, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { rd.Close() }) //nolint:errcheck
	a.sess.tunHelperStdin = wr

	require.NoError(t, a.sess.tunDown())
	require.Nil(t, a.sess.tunHelperStdin, "关闭后必须清空 helper 的 FIFO 写端")

	_, err = wr.Write([]byte("x"))
	require.Error(t, err, "FIFO 写端必须已经关闭，helper 才能从 stdin 读到 EOF")
}
