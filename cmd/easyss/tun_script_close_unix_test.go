//go:build (linux || darwin) && !headless

package main

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/scripts"
	"github.com/stretchr/testify/require"
)

// 关闭脚本的退出码契约：stub 工具放在 PATH 最前、脚本真实执行，只有以 0 退出调用方才认为
// 路由与设备已清理。漏删一条分流默认路由会让全机 IPv4 流量进一个没人读的设备（"停止 TUN 后断网"），
// 而"路由本就不存在 / 设备已消失"必须良性，否则重复关闭与 keep-alive 重放会淹没真正的失败。

// scriptArgsFixture 返回一份填满字段的脚本实参（IPv6 字段可置空），位次由
// client/tun.ScriptArgs 渲染，测试不手写位置参数。
func scriptArgsFixture(withV6 bool) tun.ScriptArgs {
	dev := tun.DeviceConfig{
		Device:       "tun-easyss-test",
		TunIP:        "198.18.0.1",
		TunGW:        "198.18.0.1",
		TunMask:      "255.255.0.0",
		LocalGateway: "192.168.3.1",
	}
	if withV6 {
		dev.TunIPV6Sub = "2001:db8::1/64"
		dev.TunGWV6 = "fe80::1"
		dev.ServerIPV6 = "2001:db8::2"
		dev.LocalGatewayV6 = "fe80::2"
	}
	return tun.NewScriptArgs(dev, "", 1500)
}

// darwinCloseScriptArgs / linuxCloseScriptArgs 是本平台关闭脚本的实参，内容由 ScriptArgs 渲染。
func darwinCloseScriptArgs(withV6 bool) []string {
	args := scriptArgsFixture(withV6)
	args.Dev.Device = "utun8"
	return args.CloseFor(tun.PlatformDarwin)
}

func linuxCloseScriptArgs() []string {
	return scriptArgsFixture(true).CloseFor(tun.PlatformLinux)
}

func testCloseScriptArgs() tun.ScriptArgs {
	return scriptArgsFixture(true)
}

// TestCloseTunScriptDarwinExitCode 固定 close_tun_dev_darwin.sh 的退出码契约。
func TestCloseTunScriptDarwinExitCode(t *testing.T) {
	requireShell(t, "sh")

	const marker = "[close_tun_dev_darwin]"
	// 9 条分流默认路由 + 1 条本地网关路由；存在 server ipv6 时再加 2 条。
	const deletesV4 = 10
	const deletesV6 = 12

	t.Run("every delete succeeds", func(t *testing.T) {
		dir := t.TempDir()
		stubTool(t, dir, "route", 0, marker)

		code, out := runScriptStubbed(t, "sh", string(scripts.CloseTunDevDarwinSh), dir, darwinCloseScriptArgs(false)...)
		require.Equal(t, 0, code, "the close script must exit 0 when every delete succeeds:\n%s", out)
		require.NotContains(t, out, "failed near", "a successful cleanup must not report a failing step")
		require.Equal(t, deletesV4, toolInvocations(t, dir, "route"),
			"every route the create script installs must be deleted")
	})

	t.Run("routes that are already gone stay successful", func(t *testing.T) {
		// 重复关闭、keep-alive 重放与从未装过 v6 路由的会话都会看到 "not in table"，这不是失败。
		dir := t.TempDir()
		failTool(t, dir, "route", "'route: writing to routing socket: not in table'", 1)

		code, out := runScriptStubbed(t, "sh", string(scripts.CloseTunDevDarwinSh), dir, darwinCloseScriptArgs(false)...)
		require.Equal(t, 0, code, "a missing route is not a cleanup failure:\n%s", out)
		require.NotContains(t, out, "failed near")
		require.Equal(t, deletesV4, toolInvocations(t, dir, "route"),
			"a benign answer must not stop the ladder early")
	})

	t.Run("a rejected delete fails the script and names the step", func(t *testing.T) {
		// 第三条路由（4.0.0.0/6）被拒绝：退出码必须非 0，且后面的删除仍要尝试——
		// 残留判定与回滚都以"整条阶梯都跑过"为前提。
		dir := t.TempDir()
		sequenceTool(t, dir, "route", "'route: permission denied'", stubStep{}, stubStep{}, stubStep{fail: true})

		code, out := runScriptStubbed(t, "sh", string(scripts.CloseTunDevDarwinSh), dir, darwinCloseScriptArgs(false)...)
		require.NotEqualf(t, 0, code, "a rejected delete must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, "failed near: route-4.0.0.0/6",
			"the failing step must be reported so the rollback path can log it")
		require.Equal(t, deletesV4, toolInvocations(t, dir, "route"),
			"one rejected block must not skip the remaining deletes")
	})

	t.Run("a missing tun gateway refuses to run", func(t *testing.T) {
		// 网关为空时 `route delete -net 1.0.0.0/8 ""` 可能被解释成不指定网关地删除该前缀，
		// 从而删掉物理网卡上的同名路由：宁可拒绝执行。
		dir := t.TempDir()
		stubTool(t, dir, "route", 0, marker)

		code, out := runScriptStubbed(t, "sh", string(scripts.CloseTunDevDarwinSh), dir, "utun8", "", "192.168.3.1", "", "", "")
		require.NotEqualf(t, 0, code, "a close script without the tun gateway must refuse to run:\n%s", out)
		require.Contains(t, out, "missing tun gateway")
		require.NoFileExists(t, filepath.Join(dir, "route.log"), "no route command may run without a gateway")
	})

	t.Run("the ipv6 deletes follow the server ipv6 argument", func(t *testing.T) {
		withV6 := t.TempDir()
		stubTool(t, withV6, "route", 0, marker)
		code, out := runScriptStubbed(t, "sh", string(scripts.CloseTunDevDarwinSh), withV6, darwinCloseScriptArgs(true)...)
		require.Equal(t, 0, code, "%s", out)
		require.Equal(t, deletesV6, toolInvocations(t, withV6, "route"))
		require.Equal(t, 2, strings.Count(toolLog(t, withV6, "route"), "-inet6"),
			"a session with a server ipv6 must delete the ::/0 route and the legacy gateway route")

		withoutV6 := t.TempDir()
		stubTool(t, withoutV6, "route", 0, marker)
		code, out = runScriptStubbed(t, "sh", string(scripts.CloseTunDevDarwinSh), withoutV6, darwinCloseScriptArgs(false)...)
		require.Equal(t, 0, code, "%s", out)
		require.Equal(t, deletesV4, toolInvocations(t, withoutV6, "route"))
		require.NotContains(t, toolLog(t, withoutV6, "route"), "-inet6",
			"a session without a server ipv6 never installed an ::/0 route")
	})
}

// TestCloseTunScriptLinuxExitCode 固定 close_tun_dev.sh 的退出码契约。
func TestCloseTunScriptLinuxExitCode(t *testing.T) {
	requireShell(t, "bash")

	const marker = "[close_tun_dev]"

	t.Run("a device that is already gone is not a failure", func(t *testing.T) {
		// 非持久化 tun 设备随最后一个 fd 消失（fd 路径的常态），内核会同时删掉它上面的路由：
		// 此时脚本必须静默成功，且不再尝试 flush/删除。
		dir := t.TempDir()
		failTool(t, dir, "ip", "'Cannot find device'", 1)

		code, out := runScriptStubbed(t, "bash", string(scripts.CloseTunDevSh), dir, linuxCloseScriptArgs()...)
		require.Equal(t, 0, code, "a device that is already gone is not a cleanup failure:\n%s", out)
		require.Empty(t, out, "nothing to clean up, nothing to report")
		require.Equal(t, 1, toolInvocations(t, dir, "ip"), "only the existence check may run")
	})

	t.Run("every command succeeds", func(t *testing.T) {
		dir := t.TempDir()
		stubTool(t, dir, "ip", 0, marker)

		code, out := runScriptStubbed(t, "bash", string(scripts.CloseTunDevSh), dir, linuxCloseScriptArgs()...)
		require.Equal(t, 0, code, "the close script must exit 0 when every command succeeds:\n%s", out)
		require.NotContains(t, out, "failed near")
		// 顺序也是契约：设备还在时 `ip tuntap del` 会以 "device or resource busy" 失败，
		// 只删设备会把分流路由留下。
		require.Equal(t, []string{
			"link show tun-easyss-test",
			"route flush dev tun-easyss-test",
			"-6 route flush dev tun-easyss-test",
			"tuntap del mode tun dev tun-easyss-test",
		}, strings.Split(strings.TrimSpace(toolLog(t, dir, "ip")), "\n"))
	})

	t.Run("a rejected route flush fails the script", func(t *testing.T) {
		dir := t.TempDir()
		sequenceTool(t, dir, "ip", "'RTNETLINK answers: Operation not permitted'", stubStep{}, stubStep{fail: true})

		code, out := runScriptStubbed(t, "bash", string(scripts.CloseTunDevSh), dir, linuxCloseScriptArgs()...)
		require.NotEqualf(t, 0, code, "a rejected flush must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, "failed near: flush-ipv4")
		require.Equal(t, 4, toolInvocations(t, dir, "ip"),
			"the remaining steps must still be attempted: a half-flushed device is the failure being reported")
	})

	t.Run("a rejected device delete fails the script", func(t *testing.T) {
		dir := t.TempDir()
		sequenceTool(t, dir, "ip", "'ioctl(TUNSETIFF): Device or resource busy'", stubStep{}, stubStep{}, stubStep{}, stubStep{fail: true})

		code, out := runScriptStubbed(t, "bash", string(scripts.CloseTunDevSh), dir, linuxCloseScriptArgs()...)
		require.NotEqualf(t, 0, code, "a device that survived the cleanup must not be reported as success:\n%s", out)
		require.Contains(t, out, "failed near: del-device")
	})

	t.Run("a device that disappears before the delete is not a failure", func(t *testing.T) {
		// 存在性检查与删除之间的竞态：fd 在那一刻被关闭，设备随之消失。
		dir := t.TempDir()
		sequenceTool(t, dir, "ip", "'Cannot find device'", stubStep{}, stubStep{}, stubStep{}, stubStep{fail: true})

		code, out := runScriptStubbed(t, "bash", string(scripts.CloseTunDevSh), dir, linuxCloseScriptArgs()...)
		require.Equal(t, 0, code, "losing the race with the kernel is not a cleanup failure:\n%s", out)
		require.NotContains(t, out, "failed near")
	})

	t.Run("a missing device argument refuses to run", func(t *testing.T) {
		dir := t.TempDir()
		stubTool(t, dir, "ip", 0, marker)

		code, out := runScriptStubbed(t, "bash", string(scripts.CloseTunDevSh), dir, "", "198.18.0.1", "192.168.3.1", "", "", "")
		require.NotEqualf(t, 0, code, "a close script without the device name must refuse to run:\n%s", out)
		require.Contains(t, out, "missing tun device")
		require.NoFileExists(t, filepath.Join(dir, "ip.log"), "no ip command may run without a device name")
	})
}

// closeScriptShell 返回本平台 runCloseScript 使用的解释器：darwin 用 sh，linux 用 bash。
func closeScriptShell() string {
	if runtime.GOOS == "darwin" {
		return "sh"
	}
	return "bash"
}

// TestRunCloseScriptReportsFailures 固定在 Go 这一层不再吞掉关闭脚本的失败：把"脚本失败"
// 当成"清理成功"，残留的分流默认路由就会把全机 IPv4 流量送进一个没人读的设备。
func TestRunCloseScriptReportsFailures(t *testing.T) {
	requireShell(t, closeScriptShell())

	origBytes, origName := scripts.CloseTunBytes, scripts.CloseTunFilename
	t.Cleanup(func() { scripts.CloseTunBytes, scripts.CloseTunFilename = origBytes, origName })
	scripts.CloseTunFilename = "close_tun_dev_reporting_test.sh"

	scriptArgs := testCloseScriptArgs()

	scripts.CloseTunBytes = []byte("#!/bin/sh\necho 'route: permission denied' >&2\nexit 1\n")
	err := runCloseScript("tun-easyss-test", scriptArgs)
	require.Error(t, err, "a failed close script must be reported, not swallowed")
	require.Contains(t, err.Error(), "permission denied",
		"the script diagnostics must survive, they are the root cause the rollback logs")

	scripts.CloseTunBytes = []byte("#!/bin/sh\nexit 0\n")
	require.NoError(t, runCloseScript("tun-easyss-test", scriptArgs))
}

// TestCleanupTunRoutesVerifiesAndRetries 固定 helper 退出时的清理契约：关闭脚本失败只在
// "路由确实还在"时才算失败，残留会被重试并按 ERROR 上报——父进程复核与提权回滚以此为依据。
func TestCleanupTunRoutesVerifiesAndRetries(t *testing.T) {
	requireShell(t, closeScriptShell())

	origBytes, origName := scripts.CloseTunBytes, scripts.CloseTunFilename
	origResidue := tunRouteResidue
	t.Cleanup(func() {
		scripts.CloseTunBytes, scripts.CloseTunFilename = origBytes, origName
		tunRouteResidue = origResidue
	})
	scripts.CloseTunFilename = "close_tun_dev_cleanup_test.sh"

	cfg := &proxy.TunConfig{
		Device:         "tun-easyss-test",
		TunGW:          "198.18.0.1",
		LocalGateway:   "192.168.3.1",
		TunGWV6:        "fe80::1",
		ServerIPV6:     "2001:db8::2",
		LocalGatewayV6: "fe80::2",
	}

	t.Run("a failed script is fine when the routes are gone", func(t *testing.T) {
		// 关闭脚本可能因为"设备已经消失"而报错，但真正的判据是路由还在不在。
		scripts.CloseTunBytes = []byte("#!/bin/sh\nexit 1\n")
		tunRouteResidue = func(string, string) (string, bool) { return "", false }

		require.NoError(t, cleanupTunRoutes(cfg.Device, cfg))
	})

	t.Run("leftover routes are retried and reported", func(t *testing.T) {
		scripts.CloseTunBytes = []byte("#!/bin/sh\nexit 1\n")
		attempts := 0
		tunRouteResidue = func(device, tunGW string) (string, bool) {
			attempts++
			require.Equal(t, cfg.Device, device)
			require.Equal(t, cfg.TunGW, tunGW)
			return "gateway: 198.18.0.1", true
		}

		err := cleanupTunRoutes(cfg.Device, cfg)
		require.Error(t, err, "routes that survived the cleanup must be reported")
		require.Contains(t, err.Error(), "still present")
		require.Equal(t, tunCleanupAttempts, attempts, "residue must be retried up to the limit")
	})

	t.Run("an attempt that clears the routes succeeds", func(t *testing.T) {
		scripts.CloseTunBytes = []byte("#!/bin/sh\nexit 0\n")
		attempts := 0
		tunRouteResidue = func(string, string) (string, bool) {
			attempts++
			return "gateway: 198.18.0.1", attempts < 2
		}

		require.NoError(t, cleanupTunRoutes(cfg.Device, cfg))
		require.Equal(t, 2, attempts, "the retry must stop as soon as the probe reports clean")
	})
}
