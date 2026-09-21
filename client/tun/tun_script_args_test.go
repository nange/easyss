package tun

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDarwinScriptArgsCarryABareV6Address 固定 darwin 创建脚本的实参形式。
//
// create_tun_dev_darwin.sh 自己给 ifconfig 的 inet6 参数补上 "/64"，而
// TunIPV6Sub 是按 linux 脚本的 "ip -6 addr replace" 需要 CIDR 形式携带
// 前缀的（默认 "2001:0db8:0:f101::1/64"）。两者叠加会拼出
// "2001:0db8:0:f101::1/64/64"：ifconfig 报 "bad value"，创建脚本以退出码 1
// 结束，于是已经配好的 IPv4 地址和路由全部被回滚，TUN 完全起不来。
//
// 这里用 New() 的默认值走一遍，断言调用方真正会交给脚本的内容。
func TestDarwinScriptArgsCarryABareV6Address(t *testing.T) {
	d := New(Config{Socks5Addr: "socks5://127.0.0.1:1"}).DeviceConfig()
	require.Equal(t, "2001:0db8:0:f101::1/64", d.TunIPV6Sub,
		"the device config keeps the CIDR form the linux script needs")

	args := darwinScriptArgs(d)
	require.Len(t, args, 8, "the script takes eight positional parameters")
	require.Equal(t, "2001:0db8:0:f101::1", args[4],
		"the darwin script appends the prefix itself, so it must receive a bare address")
	for _, arg := range args {
		require.NotContains(t, arg, "/", "no argument may carry a prefix length: %q", arg)
	}
}

// TestDarwinScriptArgsWithoutV6 确认 server ipv6 为空时脚本的 ipv6 分支
// 仍然拿不到地址：脚本正是用这个位置参数判断要不要配置 IPv6。
func TestDarwinScriptArgsWithoutV6(t *testing.T) {
	args := darwinScriptArgs(DeviceConfig{
		Device:       "utun8",
		TunIP:        "198.18.0.1",
		TunGW:        "198.18.0.1",
		LocalGateway: "192.168.3.1",
	})

	require.Len(t, args, 8)
	require.Equal(t, "", args[6], "an empty server ipv6 keeps the script's ipv6 branch a no-op")
}

// TestOsascriptRunScriptKeepsPositionalArgs 固定 darwin 提权命令的拼装方式。
//
// osascript 路径是把实参拼进一条 sh 命令行的，未加引号的空实参会被 shell 的
// 词分割丢掉，它后面的位置参数整体前移：本用例里 server_ip_v6 为空、本机有
// IPv6，前移会让创建脚本把本地网关 v6 当成 server_ip_v6，从而在服务端没有
// IPv6 时照样安装 ::/0 默认路由；关闭脚本则会把 local_gateway_v6 删成空串。
func TestOsascriptRunScriptKeepsPositionalArgs(t *testing.T) {
	args := darwinScriptArgs(DeviceConfig{
		Device:         "utun8",
		TunIP:          "198.18.0.1",
		TunGW:          "198.18.0.1",
		LocalGateway:   "192.168.3.1",
		TunIPV6Sub:     "2001:db8::1/64",
		TunGWV6:        "fe80::1",
		ServerIPV6:     "",
		LocalGatewayV6: "fe80::2",
	})
	require.Equal(t, "", args[6], "the fixture must exercise an empty server ipv6")

	require.Equal(t,
		`do shell script "sh '/tmp/t.sh' 'utun8' '198.18.0.1' '198.18.0.1' '192.168.3.1' '2001:db8::1' 'fe80::1' '' 'fe80::2'" with administrator privileges`,
		osascriptRunScript("/tmp/t.sh", args))
}

// TestShellQuote 固定单个实参的引号处理：空串必须变成可保留的空位置参数，
// 含空格的实参必须仍是一个参数，实参里的单引号按 POSIX shell 惯例转义。
func TestShellQuote(t *testing.T) {
	require.Equal(t, "''", shellQuote(""))
	require.Equal(t, "'/tmp/create tun.sh'", shellQuote("/tmp/create tun.sh"))
	require.Equal(t, `'it'\''s'`, shellQuote("it's"))
}
