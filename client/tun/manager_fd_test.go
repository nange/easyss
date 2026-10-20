//go:build darwin || linux

package tun

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// errEngineRejected 代表 tun2socks 拒绝了这次启动（引擎内部失败）。
var errEngineRejected = errors.New("engine: create stack failed")

// openTestFD 打开一个真实 fd 当作 helper 传回的 TUN fd：用例只关心 fd 归属，不要求 root。
func openTestFD(t *testing.T) int {
	t.Helper()

	fd, err := unix.Open(os.DevNull, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() {
		if fdStillOpen(fd) {
			_ = unix.Close(fd)
		}
	})
	return fd
}

// fdStillOpen 报告 fd 号当前是否仍然有效。
func fdStillOpen(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err == nil
}

// TestManagerReleasesTheHelperFDWhenCancelledEarly 守住早于 Start 的取消失败要关掉 fd：
// 否则设备随 fd 活到进程退出，helper 的关闭脚本还会因 "device or resource busy" 删不掉它。
func TestManagerReleasesTheHelperFDWhenCancelledEarly(t *testing.T) {
	stubManagerHooks(t)

	var engineStarts int
	engineStartFn = func() error { engineStarts++; return nil }

	fd := openTestFD(t)
	m := New(Config{
		Socks5Addr: "socks5://127.0.0.1:1",
		Device:     "tun-easyss-test",
		DeviceFD:   fd,
	})

	// Stop 先到、Start 后到：manager 已登记，而 Start 的 goroutine 还没被调度。
	m.Stop()
	require.ErrorIs(t, m.Start(), context.Canceled)

	require.Zero(t, engineStarts, "the engine must never be reached for a cancelled start")
	require.False(t, fdStillOpen(fd),
		"the helper fd must be released: nothing else will ever close it")
}

// TestManagerRejectsInvalidConfigBeforeTakingTheFD 固定 fd 的交接顺序：引擎在
// parseDevice 之前就会拒绝的配置，必须提前拒掉并在同一处收走 fd。于是"engine.Start
// 失败"只可能发生在 fd 已被引擎接管之后，那一段由 engine.Stop 关，Manager 不必猜归属。
func TestManagerRejectsInvalidConfigBeforeTakingTheFD(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "unparsable socks5 address",
			cfg:  Config{Socks5Addr: "://bad-proxy-url"},
			want: "invalid socks5 address",
		},
		{
			name: "unknown proxy scheme",
			cfg:  Config{Socks5Addr: "quic://127.0.0.1:1080"},
			want: "unsupported socks5 address",
		},
		{
			name: "empty socks5 address",
			cfg:  Config{Socks5Addr: ""},
			want: "empty socks5 address",
		},
		{
			name: "invalid log level",
			cfg:  Config{Socks5Addr: "socks5://127.0.0.1:1080", LogLevel: "not-a-log-level"},
			want: "invalid log level",
		},
		{
			name: "udp timeout below one second",
			cfg:  Config{Socks5Addr: "socks5://127.0.0.1:1080", UDPTimeout: 500 * 1e6},
			want: "invalid udp timeout",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubManagerHooks(t)

			var engineStarts int
			engineStartFn = func() error { engineStarts++; return nil }

			fd := openTestFD(t)
			tc.cfg.Device = "tun-easyss-test"
			tc.cfg.DeviceFD = fd

			err := New(tc.cfg).Start()
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)

			require.Zero(t, engineStarts,
				"the engine must never see a configuration it is going to reject before parseDevice")
			require.False(t, fdStillOpen(fd),
				"the fd was released before the engine could take it, so it must be closed")
		})
	}
}

// TestManagerLeavesTheFDOwnershipToTheEngineOnceItStarts 是上一条的边界：进入
// engine.Start 后 fd 归 tun2socks（parseDevice 包装设备，失败时也可能已关闭），
// Manager 再关就是猜。
func TestManagerLeavesTheFDOwnershipToTheEngineOnceItStarts(t *testing.T) {
	stubManagerHooks(t)

	engineStartFn = func() error { return errEngineRejected }

	fd := openTestFD(t)
	m := New(Config{
		Socks5Addr: "socks5://127.0.0.1:1",
		Device:     "tun-easyss-test",
		DeviceFD:   fd,
	})

	require.Error(t, m.Start())

	require.True(t, fdStillOpen(fd),
		"after engine.Start the fd is the engine's: closing it here would be a guess")
}
