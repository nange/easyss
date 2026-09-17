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
