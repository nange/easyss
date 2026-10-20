//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/scripts"
	"github.com/stretchr/testify/require"
)

// TestRunCreateScriptStripsV6Prefix 固定 helper 路径的实参契约：交给
// create_tun_dev_darwin.sh 的 IPv6 地址必须裸地址。脚本自己拼 "/64"，而 TunIPV6Sub
// 默认带前缀（linux 需要 CIDR），透传会拼出 "/64/64"，ifconfig 报 "bad value" 退出 1，
// TUN 完全起不来。内嵌脚本换成只记录实参的桩：要证明的是参数。
func TestRunCreateScriptStripsV6Prefix(t *testing.T) {
	origBytes, origName := scripts.CreateTunBytes, scripts.CreateTunFilename
	t.Cleanup(func() { scripts.CreateTunBytes, scripts.CreateTunFilename = origBytes, origName })

	marker := filepath.Join(t.TempDir(), "create-args")
	scripts.CreateTunFilename = "create_tun_dev_darwin_args_test.sh"
	scripts.CreateTunBytes = []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + marker + "\"\n")

	args := tun.NewScriptArgs(tun.DeviceConfig{
		Device:         "utun9",
		TunIP:          "198.18.0.1",
		TunGW:          "198.18.0.1",
		TunMask:        "255.255.0.0",
		TunIPV6Sub:     "2001:0db8:0:f101::1/64",
		TunGWV6:        "fe80::1",
		ServerIPV6:     "2001:db8::2",
		LocalGateway:   "192.168.3.1",
		LocalGatewayV6: "fe80::2",
	}, "", 8500)
	require.NoError(t, runCreateScript("utun9", args))

	data, err := os.ReadFile(marker)
	require.NoError(t, err, "the create script did not run")

	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Equal(t, []string{
		"utun9", "198.18.0.1", "198.18.0.1", "192.168.3.1",
		"2001:0db8:0:f101::1", "fe80::1", "2001:db8::2", "fe80::2", "8500",
	}, got, "the script appends the prefix itself, so the address must arrive bare")
}

// TestBareV6Addr 覆盖 ScriptArgs 的去前缀：带前缀去掉，裸地址原样返回。
func TestBareV6Addr(t *testing.T) {
	require.Equal(t, "2001:db8::1", tun.NewScriptArgs(tun.DeviceConfig{TunIPV6Sub: "2001:db8::1/64"}, "", 1500).
		CreateFor(tun.PlatformDarwin)[4])
	require.Equal(t, "2001:db8::1", tun.NewScriptArgs(tun.DeviceConfig{TunIPV6Sub: "2001:db8::1"}, "", 1500).
		CreateFor(tun.PlatformDarwin)[4])
	require.Equal(t, "", tun.NewScriptArgs(tun.DeviceConfig{}, "", 1500).CreateFor(tun.PlatformDarwin)[4])
}

// TestTunRouteResidueUsesTheTunGateway 钉住 darwin 的残留判定：判据是本会话的 TUN
// 网关而不是设备名——内核分配的是 utunN，请求名可能与别的 utun 重名、也未必等于
// 实际分配到的名字。造真实残留路由需要 root，故只替换 routeProbeCmd。
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
		// 没有网关时只能退回设备名：别的 utun 占用该名字会被误判为残留，是已知代价。
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
