package tun

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// scriptFixture 是一份填满所有字段的设备配置：空字段会让"位次错位"这类
// 缺陷恰好被空串掩盖（例如 server ipv6 为空时，后面的参数整体前移也不会
// 立刻显出差别）。
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

// TestCreateScriptArgsLayoutPerPlatform 固定三平台创建脚本的位次。它是
// ScriptArgs 存在的理由：脚本契约是位置参数，而三套位次并不相同
// （windows 的第 4 位是掩码、第 8 位是 DNS；linux/darwin 的第 2 位是
// 带前缀的地址）。任何一处挪位都会在这里失败，而不是等到运行时由脚本
// 报出 "failed near"。
func TestCreateScriptArgsLayoutPerPlatform(t *testing.T) {
	args := NewScriptArgs(scriptFixture(), "8.8.8.8", 1500)

	t.Run("linux", func(t *testing.T) {
		// 第 2 位是"地址/掩码"：iproute2 的 `ip addr replace` 接受点分掩码
		// （198.18.0.1/255.255.0.0 等价于 /16），这是既有行为，与 `ip link
		// set mtu` 一样由脚本消费。
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

// TestCloseScriptArgsLayoutPerPlatform 固定关闭脚本的位次：windows 只取三个
// 参数且第 3 位是裸 IPv6 地址（netsh delete address 拒绝带前缀的地址），
// linux/darwin 是六个按统一顺序补齐的网关（linux 脚本只读设备名，其余实参
// 仅为与 darwin 共用同一套布局）。
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

// TestScriptArgsWithoutV6 确认服务端没有 IPv6 时，第 7 个位置参数是空串：
// 两个创建脚本都用它判断要不要安装 IPv6 地址与默认路由。
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

// TestNewScriptArgsNormalizesMTU 固定 MTU 的归一化位置：它是跨进程传递的值
// （helper 从 GET /tun 拿到），未配置的 0 必须落到与主进程相同的默认值，
// 否则设备侧与 netstack 会悄悄分叉。
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

// TestPlatformMatchesTheRunningOS 固定便捷方法确实按本机平台渲染：调用点
// （Manager 的脚本执行、helper 的 runCreateScript）用的都是它。
func TestPlatformMatchesTheRunningOS(t *testing.T) {
	require.Equal(t, ScriptPlatform(runtime.GOOS), Platform())

	args := NewScriptArgs(scriptFixture(), "8.8.8.8", 1500)
	require.Equal(t, args.CreateFor(Platform()), args.Create())
	require.Equal(t, args.CloseFor(Platform()), args.Close())
}

// TestDarwinScriptArgsCarryABareV6Address 固定 darwin 脚本实参的形式。
//
// create_tun_dev_darwin.sh 自己给 ifconfig 的 inet6 参数补上 "/64"，而
// TunIPV6Sub 是按 linux 脚本的 "ip -6 addr replace" 需要 CIDR 形式携带
// 前缀的（默认 "2001:0db8:0:f101::1/64"）。两者叠加会拼出
// "2001:0db8:0:f101::1/64/64"：ifconfig 报 "bad value"，创建脚本以退出码 1
// 结束，于是已经配好的 IPv4 地址和路由全部被回滚，TUN 完全起不来。
//
// 这里用 New() 的默认值走一遍，断言调用方真正会交给脚本的内容。
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

// TestOsascriptRunScriptKeepsPositionalArgs 固定 darwin 提权命令的拼装方式。
//
// osascript 路径是把实参拼进一条 sh 命令行的，未加引号的空实参会被 shell 的
// 词分割丢掉，它后面的位置参数整体前移：本用例里 server_ip_v6 为空、本机有
// IPv6，前移会让创建脚本把本地网关 v6 当成 server_ip_v6，从而在服务端没有
// IPv6 时照样安装 ::/0 默认路由；关闭脚本则会把 local_gateway_v6 删成空串。
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

// TestShellQuote 固定单个实参的引号处理：空串必须变成可保留的空位置参数，
// 含空格的实参必须仍是一个参数，实参里的单引号按 POSIX shell 惯例转义。
func TestShellQuote(t *testing.T) {
	require.Equal(t, "''", shellQuote(""))
	require.Equal(t, "'/tmp/create tun.sh'", shellQuote("/tmp/create tun.sh"))
	require.Equal(t, `'it'\''s'`, shellQuote("it's"))
}
