package tun

import (
	"errors"
	"testing"

	"github.com/nange/easyss/v3/config"
	"github.com/stretchr/testify/require"
)

// stubIfaceMTU 让该 Manager 的接口 MTU 查询返回固定值，无需真实 TUN 设备；
// 返回的调用次数也是断言对象（非 fd 路径不应去查设备）。
func stubIfaceMTU(m *Manager, mtu int, err error) *int {
	calls := 0
	m.plat.ifaceMTU = func(string) (int, error) {
		calls++
		return mtu, err
	}
	return &calls
}

// TestNewNormalizesMTU 固定 client/tun 这一侧也走唯一的归一化入口：
// 未配置（或非法）的值必须落到与设备创建方相同的默认值。若这里保留字面量，
// 配置层面改了默认值就会让 netstack 与设备的 MTU 悄悄分叉。
func TestNewNormalizesMTU(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   int
		want int
	}{
		{"未配置", 0, config.DefaultTunMTU},
		{"低于下界", 100, config.MinTunMTU},
		{"高于上界", 1 << 20, config.MaxTunMTU},
		{"区间内的值原样保留", 8500, 8500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", MTU: tc.in})
			require.Equal(t, tc.want, m.cfg.MTU)
		})
	}
}

// TestEngineMTURaisesTheNetstackMTUOnTheFDPath 守住静默丢包：fd 路径上设备由 helper
// 创建，主进程只能设 netstack 的 MTU，而 tun2socks 会直接丢掉超过它的包。
func TestEngineMTURaisesTheNetstackMTUOnTheFDPath(t *testing.T) {
	t.Parallel()

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "utun9", DeviceFD: 7, MTU: 1500})
	stubIfaceMTU(m, 8500, nil)
	require.Equal(t, 8500, m.engineMTU(), "the device mtu must win: a smaller netstack mtu drops packets")
}

// TestEngineMTUCapsAnOutOfRangeDeviceMTU 固定兜底的边界：设备的 MTU 超出可配置
// 区间只可能是外部改动，netstack 的 MTU 同时也是每包读取缓冲的大小，因此不能
// 无上限地跟着走。TCP 不受影响（本机应用发出的段不会超过通告的 MSS）。
func TestEngineMTUCapsAnOutOfRangeDeviceMTU(t *testing.T) {
	t.Parallel()

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "utun9", DeviceFD: 7, MTU: 1500})
	stubIfaceMTU(m, 1<<16-1, nil)
	require.Equal(t, config.MaxTunMTU, m.engineMTU())
}

// TestEngineMTUKeepsTheConfiguredMTUWhenTheDeviceIsSmaller 固定另一个方向：
// 设备更小不会丢包（netstack 的 MTU 只是上限），因此不能反过来把配置值悄悄
// 改小——那等于在用户不知情的情况下改掉了他设置的 MTU。
func TestEngineMTUKeepsTheConfiguredMTUWhenTheDeviceIsSmaller(t *testing.T) {
	t.Parallel()

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "utun9", DeviceFD: 7, MTU: 1500})
	stubIfaceMTU(m, 1400, nil)
	require.Equal(t, 1500, m.engineMTU())
}

// TestEngineMTUFallsBackToTheConfiguredMTUWhenTheDeviceIsUnknown 固定查询失败
// 时的行为：既不能确认也不能修正，因此保持配置值——猜一个 MTU 更危险。
func TestEngineMTUFallsBackToTheConfiguredMTUWhenTheDeviceIsUnknown(t *testing.T) {
	t.Parallel()

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "utun9", DeviceFD: 7, MTU: 1500})
	stubIfaceMTU(m, 0, errors.New("no such interface"))
	require.Equal(t, 1500, m.engineMTU())
}

// TestEngineMTUSkipsTheDeviceProbeWithoutFD 说明非 fd 路径的分工：设备还不存在，
// 或者即将由 tun2socks 按同一个值重建，因此这一侧不做查询也不做修正。
func TestEngineMTUSkipsTheDeviceProbeWithoutFD(t *testing.T) {
	t.Parallel()

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "utun9", MTU: 1500})
	calls := stubIfaceMTU(m, 8500, nil)
	require.Equal(t, 1500, m.engineMTU())
	require.Zero(t, *calls, "the device does not exist yet on the name path")
}

// TestWarnOnMTUMismatchOnlyProbesTheNamePath 固定启动后的核对范围：fd 路径已经
// 由 engineMTU 对齐，不必再查一次；非 fd 路径（Windows 的 wintun 适配器只能由
// 创建脚本设置 MTU）才需要把"配置了却没生效"记进日志。
func TestWarnOnMTUMismatchOnlyProbesTheNamePath(t *testing.T) {
	t.Parallel()

	fd := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "utun9", DeviceFD: 7, MTU: 1500})
	calls := stubIfaceMTU(fd, 1400, nil)
	probes := fd.engineMTU()
	require.Equal(t, 1, *calls, "engineMTU resolves the device mtu on the fd path")
	*calls = 0
	fd.warnOnMTUMismatch(probes)
	require.Zero(t, *calls, "the fd path is already reconciled by engineMTU")

	named := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "utun9", MTU: 1500})
	namedCalls := stubIfaceMTU(named, 1400, nil)
	named.warnOnMTUMismatch(named.cfg.MTU)
	require.Equal(t, 1, *namedCalls, "the name path must verify what the device actually got")

	// 查不到设备时保持静默：这只说明接口名还没出现，不代表配置有问题。
	unknown := stubIfaceMTU(named, 0, errors.New("no such interface"))
	named.warnOnMTUMismatch(named.cfg.MTU)
	require.Equal(t, 1, *unknown, "the probe still runs, it just does not log")
}
