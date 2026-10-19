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

// openTestFD 打开一个真实的 fd，当作提权 helper 传回的 TUN fd。它不要求 root：
// 这些用例只关心 fd 的归属，不关心它指向什么设备。
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

// TestManagerReleasesTheHelperFDWhenCancelledEarly 固定 fd 路径上的另一半。
//
// 非 root 的提权 helper 把 TUN fd 传回主进程之后，Start 可能还没被调度到就
// 收到了 Stop（见 TestManagerStopBeforeStartGoroutineRuns）。此时 Start 在动
// 任何系统状态之前就返回 context.Canceled，那个 fd 从未进入 tun2socks：
// 不关掉它，设备会随 fd 存活到进程退出，helper 的关闭脚本还会因
// "device or resource busy" 删不掉它。
//
// 这个关闭是安全的，因为调用点本身就在证明"还没进引擎"——而不是事后按 fd
// 身份去猜（两个独立 socket 的 ino/dev 都是 0，字符设备的 dev/ino/rdev/mode
// 也完全相同，猜不准）。
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

	// Stop 先到、Start 后到：tunUpViaHelper 登记 manager 之后，Start 所在
	// goroutine 可能还没被调度到。
	m.Stop()
	require.ErrorIs(t, m.Start(), context.Canceled)

	require.Zero(t, engineStarts, "the engine must never be reached for a cancelled start")
	require.False(t, fdStillOpen(fd),
		"the helper fd must be released: nothing else will ever close it")
}

// TestManagerRejectsInvalidConfigBeforeTakingTheFD 是方案 A 的核心：
// 引擎在 parseDevice 之前就会拒绝的配置，必须在 fd 交出去之前被拒掉，
// 并且在同一个调用里把 fd 收掉（此时"还没进引擎"是调用点自己的事实）。
//
// 这样一来，"engine.Start 失败"只可能发生在 fd 已经被引擎接管之后——那一段
// 由 engine.Stop 负责关闭，Manager 不需要（也不应该）去猜 fd 的归属。
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

// TestManagerLeavesTheFDOwnershipToTheEngineOnceItStarts 是上一条的边界：
// 一旦进入 engine.Start，fd 就归 tun2socks 了（它在 parseDevice 里包装设备，
// 失败时也可能已经关闭），Manager 不得再插手动它。
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
