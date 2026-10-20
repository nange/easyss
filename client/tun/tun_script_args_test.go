package tun

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// scriptFixture 是填满所有字段的设备配置：空字段会让"位次错位"恰好被空串掩盖
// （server ipv6 为空时，后面参数整体前移也不会显出差别）。
func scriptFixture() DeviceConfig {
	return DeviceConfig{
		Device:         "utun8",
		TunIP:          "198.18.0.1",
		TunGW:          "198.18.0.1",
		TunMask:        "255.255.0.0",
		TunIPV6Sub:     "2001:0db8:0:f101::1/64",
		TunGWV6:        "fe80::1",
		ServerIPV6:     "2001:db8::2",
		LocalGateway:   "192.168.3.1",
		LocalGatewayV6: "fe80::2",
	}
}

// TestCreateScriptArgsLayoutPerPlatform 固定三平台创建脚本的位次：脚本契约就是位置参数，
// 而三套位次并不相同。挪位必须在这里失败，而不是等运行时由脚本报出 "failed near"。
func TestCreateScriptArgsLayoutPerPlatform(t *testing.T) {
	args := NewScriptArgs(scriptFixture(), "8.8.8.8", 1500)

	t.Run("linux", func(t *testing.T) {
		// 第 2 位是"地址/掩码"：iproute2 的 `ip addr replace` 接受点分掩码（等价于 /16）。
		require.Equal(t, []string{
			"utun8", "198.18.0.1/255.255.0.0", "198.18.0.1", "192.168.3.1",
			"2001:0db8:0:f101::1/64", "fe80::1", "2001:db8::2", "fe80::2", "1500",
		}, args.CreateFor(PlatformLinux),
			"linux 的第 2 位是带掩码的地址，第 5 位是 CIDR 形式的 IPv6")
	})

	t.Run("darwin", func(t *testing.T) {
		require.Equal(t, []string{
			"utun8", "198.18.0.1", "198.18.0.1", "192.168.3.1",
			"2001:0db8:0:f101::1", "fe80::1", "2001:db8::2", "fe80::2", "1500",
		}, args.CreateFor(PlatformDarwin),
			"darwin 自己给 ifconfig 补 /64，第 5 位必须是裸地址")
	})

	t.Run("windows", func(t *testing.T) {
		require.Equal(t, []string{
			"utun8", "198.18.0.1", "198.18.0.1", "255.255.0.0",
			"2001:0db8:0:f101::1/64", "fe80::1", "2001:db8::2", "8.8.8.8", "1500",
		}, args.CreateFor(PlatformWindows),
			"windows 的第 4 位是掩码、第 8 位是适配器 DNS")
	})
}

// TestCloseScriptArgsLayoutPerPlatform 固定关闭脚本的位次：windows 只取三个参数且第 3 位是裸 IPv6
// （netsh delete address 拒绝带前缀的地址），linux/darwin 是六个按统一顺序补齐的网关。
func TestCloseScriptArgsLayoutPerPlatform(t *testing.T) {
	args := NewScriptArgs(scriptFixture(), "8.8.8.8", 1500)

	require.Equal(t, []string{
		"utun8", "198.18.0.1", "192.168.3.1", "fe80::1", "2001:db8::2", "fe80::2",
	}, args.CloseFor(PlatformLinux))
	require.Equal(t, []string{
		"utun8", "198.18.0.1", "192.168.3.1", "fe80::1", "2001:db8::2", "fe80::2",
	}, args.CloseFor(PlatformDarwin))
	require.Equal(t, []string{
		"utun8", "198.18.0.1", "2001:0db8:0:f101::1",
	}, args.CloseFor(PlatformWindows))
}

// TestScriptArgsWithoutV6 确认服务端没有 IPv6 时第 7 位是空串：创建脚本靠它决定是否装 IPv6 地址与默认路由。
func TestScriptArgsWithoutV6(t *testing.T) {
	dev := DeviceConfig{
		Device:       "utun8",
		TunIP:        "198.18.0.1",
		TunGW:        "198.18.0.1",
		LocalGateway: "192.168.3.1",
	}

	args := NewScriptArgs(dev, "", 1500)
	for _, platform := range []ScriptPlatform{PlatformLinux, PlatformDarwin, PlatformWindows} {
		got := args.CreateFor(platform)
		require.Len(t, got, 9, "%s: the create script takes nine positional parameters", platform)
		require.Equal(t, "", got[6], "%s: an empty server ipv6 keeps the script's ipv6 branch a no-op", platform)
	}
}

// TestNewScriptArgsNormalizesMTU 固定 MTU 在这里归一：它跨进程传递（helper 从 GET /tun 拿到），
// 0 必须落到与主进程相同的默认值，否则设备侧与 netstack 会悄悄分叉。
func TestNewScriptArgsNormalizesMTU(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want string
	}{
		{"未配置", 0, "1500"},
		{"低于下界", 100, "1280"},
		{"高于上界", 1 << 20, "9000"},
		{"区间内原样保留", 8500, "8500"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := NewScriptArgs(scriptFixture(), "", tc.in)
			require.Equal(t, tc.want, args.CreateFor(PlatformLinux)[8])
		})
	}
}

func TestPlatformMatchesTheRunningOS(t *testing.T) {
	require.Equal(t, ScriptPlatform(runtime.GOOS), Platform())

	args := NewScriptArgs(scriptFixture(), "8.8.8.8", 1500)
	require.Equal(t, args.CreateFor(Platform()), args.Create())
	require.Equal(t, args.CloseFor(Platform()), args.Close())
}

// TestDarwinScriptArgsCarryABareV6Address 固定 darwin 拿到的是裸 IPv6：create_tun_dev_darwin.sh 自己给
// ifconfig 补 "/64"，而 TunIPV6Sub 为 linux 的 "ip -6 addr replace" 保留 CIDR 形式，叠加会拼出
// "...::1/64/64"——ifconfig 报 bad value、创建脚本以 1 退出，已配好的地址与路由全被回滚。
func TestDarwinScriptArgsCarryABareV6Address(t *testing.T) {
	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1"})
	d := m.DeviceConfig()
	require.Equal(t, "2001:0db8:0:f101::1/64", d.TunIPV6Sub,
		"the device config keeps the CIDR form the linux script needs")

	args := NewScriptArgs(d, m.cfg.DNSServer, m.cfg.MTU).CreateFor(PlatformDarwin)
	require.Len(t, args, 9, "the script takes nine positional parameters")
	require.Equal(t, "2001:0db8:0:f101::1", args[4],
		"the darwin script appends the prefix itself, so it must receive a bare address")
	require.Equal(t, "1500", args[8],
		"the last argument is the MTU the script writes into the device")
	for _, arg := range args {
		require.NotContains(t, arg, "/", "no argument may carry a prefix length: %q", arg)
	}
}

// TestOsascriptRunScriptKeepsPositionalArgs 固定 darwin 提权命令的拼装：实参被拼进一条 sh 命令行，
// 未加引号的空实参会被 shell 词分割丢掉、后面的参数整体前移——创建脚本会把本地网关 v6 当成 server_ipv6
// 照样装 ::/0 路由，关闭脚本则会把 local_gateway_v6 删成空串。
func TestOsascriptRunScriptKeepsPositionalArgs(t *testing.T) {
	dev := DeviceConfig{
		Device:         "utun8",
		TunIP:          "198.18.0.1",
		TunGW:          "198.18.0.1",
		LocalGateway:   "192.168.3.1",
		TunIPV6Sub:     "2001:db8::1/64",
		TunGWV6:        "fe80::1",
		LocalGatewayV6: "fe80::2",
	}
	args := NewScriptArgs(dev, "", 1500).CreateFor(PlatformDarwin)
	require.Equal(t, "", args[6], "the fixture must exercise an empty server ipv6")

	require.Equal(t,
		`do shell script "sh '/tmp/t.sh' 'utun8' '198.18.0.1' '198.18.0.1' '192.168.3.1' '2001:db8::1' 'fe80::1' '' 'fe80::2' '1500'" with administrator privileges`,
		osascriptRunScript("/tmp/t.sh", args))
}

// TestShellQuote 固定引号处理：空串变成可保留的空位置参数，含空格的仍是一个参数，单引号按 POSIX 惯例转义。
func TestShellQuote(t *testing.T) {
	require.Equal(t, "''", shellQuote(""))
	require.Equal(t, "'/tmp/create tun.sh'", shellQuote("/tmp/create tun.sh"))
	require.Equal(t, `'it'\''s'`, shellQuote("it's"))
}

// TestZeroScriptArgsRenderAnEmptyMTU 固定零值安全：非正 MTU 必须渲染成空串，脚本据此跳过 MTU 步骤。
// 渲染成 "0" 会让创建脚本执行 "ip link set dev ... mtu 0"，整条命令失败。零值安全是类型自己的性质，
// 不能依赖调用方总走 NewScriptArgs（它会把 MTU 归一到 [1280, 9000]）。
func TestZeroScriptArgsRenderAnEmptyMTU(t *testing.T) {
	var zero ScriptArgs
	for _, platform := range []ScriptPlatform{PlatformLinux, PlatformDarwin, PlatformWindows} {
		args := zero.CreateFor(platform)
		require.Len(t, args, 9, "%s: the create script takes nine positional parameters", platform)
		require.Equal(t, "", args[8],
			"%s: 非正 MTU 必须渲染成空串，脚本据此跳过 MTU 步骤", platform)
	}

	neg := ScriptArgs{MTU: -5}
	require.Equal(t, "", neg.CreateFor(PlatformLinux)[8])
}
