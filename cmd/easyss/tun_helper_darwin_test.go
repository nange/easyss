//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/scripts"
	"github.com/stretchr/testify/require"
)

// TestRunCreateScriptStripsV6Prefix 固定 helper 路径上的实参契约：
// runCreateScript 交给 create_tun_dev_darwin.sh 的 IPv6 地址必须是裸地址。
//
// 脚本自己把 "/64" 拼到 ifconfig 的 inet6 参数上，而 TunIPV6Sub 来自
// client/tun 的默认值 "2001:0db8:0:f101::1/64"（linux 脚本的
// "ip -6 addr replace" 需要 CIDR 形式），直接透传会拼出 ".../64/64"。
// ifconfig 报 "bad value" 并以退出码 1 结束，helper 于是对托盘报告
// "run create script" 失败，TUN 完全起不来——正是这个测试要拦住的回归。
//
// 真实的创建脚本需要 root 而且会重配运行测试的机器的网络，因此这里把内嵌
// 脚本替换成记录自身实参的脚本：本测试要证明的是传给脚本的参数，
// 而不是脚本本身（脚本由 tun_script_unix_test.go 覆盖）。
func TestRunCreateScriptStripsV6Prefix(t *testing.T) {
	origBytes, origName := scripts.CreateTunBytes, scripts.CreateTunFilename
	t.Cleanup(func() { scripts.CreateTunBytes, scripts.CreateTunFilename = origBytes, origName })

	marker := filepath.Join(t.TempDir(), "create-args")
	scripts.CreateTunFilename = "create_tun_dev_darwin_args_test.sh"
	scripts.CreateTunBytes = []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + marker + "\"\n")

	require.NoError(t, runCreateScript("utun9", "198.18.0.1", "198.18.0.1", "192.168.3.1",
		"2001:0db8:0:f101::1/64", "fe80::1", "2001:db8::2", "fe80::2", 8500, "192.0.2.7 198.51.100.9"))

	data, err := os.ReadFile(marker)
	require.NoError(t, err, "the create script did not run")

	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Equal(t, []string{
		"utun9", "198.18.0.1", "198.18.0.1", "192.168.3.1",
		"2001:0db8:0:f101::1", "fe80::1", "2001:db8::2", "fe80::2", "8500", "192.0.2.7 198.51.100.9",
	}, got, "the script appends the prefix itself, so the address must arrive bare")
}

// TestBareV6Addr 覆盖 helper 侧的去前缀辅助函数：带前缀的输入去掉前缀，
// 不带前缀的输入原样返回（TunIPV6Sub 也可能已经是裸地址）。
func TestBareV6Addr(t *testing.T) {
	require.Equal(t, "2001:db8::1", bareV6Addr("2001:db8::1/64"))
	require.Equal(t, "2001:db8::1", bareV6Addr("2001:db8::1"))
	require.Equal(t, "", bareV6Addr(""))
}

// TestTunRouteResidueUsesTheTunGateway 用注入的探测输出钉住 darwin 的残留判定：
// 判据是本会话的 TUN 网关，而不是设备名（内核分配的是 utunN，请求名可能既与别的
// utun 设备重名、也未必等于实际分配到的名字）。
//
// 真实的残留路由需要 root 才能造出来，因此这里替换的是命令执行（routeProbeCmd），
// 脚本与真实系统路由表都不参与。
func TestTunRouteResidueUsesTheTunGateway(t *testing.T) {
	const (
		viaTun = "   route to: 1.1.1.1\n" +
			"destination: 1.0.0.0\n" +
			"       mask: 255.0.0.0\n" +
			"    gateway: 198.18.0.1\n" +
			"  interface: utun9\n"
		viaPhysical = "   route to: 1.1.1.1\n" +
			"destination: 0.0.0.0\n" +
			"       mask: 0.0.0.0\n" +
			"    gateway: 192.168.3.1\n" +
			"  interface: en0\n"
	)

	t.Run("still routed via the tun gateway", func(t *testing.T) {
		calls := stubRouteProbe(t, viaTun)

		out, leftover := tunRouteResidue("utun9", "198.18.0.1")
		require.True(t, leftover, "the session's own gateway means traffic still enters the dead device")
		require.Contains(t, out, "gateway: 198.18.0.1")
		require.Equal(t, []string{"route", "-n", "get", "1.1.1.1"}, (*calls)[0],
			"the darwin probe is `route -n get <probe>`")
	})

	t.Run("routed via the physical gateway", func(t *testing.T) {
		stubRouteProbe(t, viaPhysical)

		_, leftover := tunRouteResidue("utun9", "198.18.0.1")
		require.False(t, leftover, "the physical default route means the teardown worked")
	})

	t.Run("without a gateway the device name is the fallback", func(t *testing.T) {
		// 网关信息缺失时只能退回设备名：这里模拟"另一个 utun 设备占用了请求名"，
		// 判定结果为残留是这种兜底判据的已知代价，注释与它保持一致。
		stubRouteProbe(t, viaTun)

		_, leftover := tunRouteResidue("utun9", "")
		require.True(t, leftover)
	})

	t.Run("no probe output at all", func(t *testing.T) {
		stubRouteProbe(t, "")

		_, leftover := tunRouteResidue("utun9", "198.18.0.1")
		require.False(t, leftover, "unreadable output must not be reported as residue")
	})
}
