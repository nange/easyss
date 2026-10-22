//go:build (darwin || linux) && !headless

package tunhelper

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/util"
	"github.com/stretchr/testify/require"
)

// testTunOps 返回探测/回滚可控的 ops，控制锁落在临时目录：真实实现要 root 才能造出
// 残留路由，也会改写运行测试的机器的路由表。
func testTunOps(t *testing.T) ops {
	t.Helper()
	return ops{
		lockPath: filepath.Join(t.TempDir(), "easyss-tun.lock"),
		probe:    func(string, string) (string, bool) { return "", false },
		rollback: func(tun.DeviceConfig) error { return nil },
	}
}

// TestWaitTunHelperExit 固定"父进程如何判断提权 helper 是否已经退出"：helper 由
// osascript/pkexec 后台拉起（PPID 为 1），父进程拿不到它的 pid，唯一可靠的信号是
// 它持有的文件锁——内核会在进程退出时释放它，被 kill -9 也一样。
func TestWaitTunHelperExit(t *testing.T) {
	ops := testTunOps(t)

	t.Run("no lock file yet", func(t *testing.T) {
		require.NoError(t, waitTunHelperExit(ops.lockPath, 50*time.Millisecond),
			"从未启动过 helper 时不该等待或报错")
	})

	holder, err := os.OpenFile(ops.lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	require.NoError(t, err)
	t.Cleanup(func() { holder.Close() }) //nolint:errcheck

	require.NoError(t, util.FlockWait(holder, time.Second), "模拟仍活着的 helper")

	err = waitTunHelperExit(ops.lockPath, 100*time.Millisecond)
	require.Error(t, err, "仍持有锁的 helper 必须被识别为还活着")
	require.Contains(t, err.Error(), "still holds")

	require.NoError(t, util.Unflock(holder))
	require.NoError(t, waitTunHelperExit(ops.lockPath, time.Second), "helper 退出后必须立刻放行")
}

// TestVerifyTunTeardown 覆盖拆除后的复核：只要探测到 TUN 路由残留就提权回滚，
// 回滚仍失败则把问题报给调用方（由它通知用户），绝不让"路由还在、流量黑洞"
// 静默通过。
func TestVerifyTunTeardown(t *testing.T) {
	ops := testTunOps(t)

	dev := tun.DeviceConfig{Device: "utun9", TunGW: "198.18.0.1"}

	t.Run("clean teardown does not roll back", func(t *testing.T) {
		rollbacks := 0
		ops.probe = func(string, string) (string, bool) { return "", false }
		ops.rollback = func(tun.DeviceConfig) error {
			rollbacks++
			return nil
		}

		require.NoError(t, ops.verify(dev))
		require.Zero(t, rollbacks)
	})

	t.Run("leftover routes are rolled back and re-checked", func(t *testing.T) {
		probes, rollbacks := 0, 0
		var gotDevice, gotGateway string
		ops.probe = func(device, tunGW string) (string, bool) {
			probes++
			gotDevice, gotGateway = device, tunGW
			return "gateway: 198.18.0.1", probes == 1 // 回滚之后探测干净了
		}
		ops.rollback = func(tun.DeviceConfig) error {
			rollbacks++
			return nil
		}

		require.NoError(t, ops.verify(dev))
		require.Equal(t, 1, rollbacks)
		require.Equal(t, 2, probes, "回滚之后必须重新探测一次")
		require.Equal(t, "utun9", gotDevice)
		require.Equal(t, "198.18.0.1", gotGateway)
	})

	t.Run("rollback failure is reported", func(t *testing.T) {
		errBoom := errors.New("no privilege")
		ops.probe = func(string, string) (string, bool) { return "gateway: 198.18.0.1", true }
		ops.rollback = func(tun.DeviceConfig) error { return errBoom }

		err := ops.verify(dev)
		require.ErrorIs(t, err, errBoom)
	})

	t.Run("residue after rollback is reported", func(t *testing.T) {
		rollbacks := 0
		ops.probe = func(string, string) (string, bool) { return "gateway: 198.18.0.1", true }
		ops.rollback = func(tun.DeviceConfig) error {
			rollbacks++
			return nil
		}

		err := ops.verify(dev)
		require.Error(t, err)
		require.Contains(t, err.Error(), "仍然残留")
		require.Equal(t, 1, rollbacks)
	})
}
