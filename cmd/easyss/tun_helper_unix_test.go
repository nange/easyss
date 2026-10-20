//go:build darwin || linux

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/stretchr/testify/require"
)

// fdTestSocketPath 在独立目录里返回短 socket 路径：sun_path 上限约 104 字节，
// 而 t.TempDir() 嵌了测试名，在 macOS 上会超。
func fdTestSocketPath(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "easyss-fd")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	return filepath.Join(dir, "fd.sock")
}

// TestReceiveFdReportsAFailedHelperImmediately 防止父进程在 fd socket 上盲等：helper
// 在发出 fd 之前就失败（如创建脚本非零退出）时，必须靠 notifyStartFailure 连接但不
// 带 fd 宣告放弃，让父进程立刻连同原因报告，而不是等满 30s 的 accept 截止时间。
func TestReceiveFdReportsAFailedHelperImmediately(t *testing.T) {
	const reason = `run create script: exit status 1: "[create_tun_dev] failed near: route"`

	socketPath := fdTestSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint:errcheck

	notified := make(chan struct{})
	go func() {
		defer close(notified)
		notifyStartFailure(socketPath, errors.New(reason))
	}()

	start := time.Now()
	_, err = ReceiveFd(listener)
	elapsed := time.Since(start)
	<-notified

	require.Error(t, err, "a connection that carries no fd is a failed helper, not a started one")
	require.Less(t, elapsed, 5*time.Second,
		"the parent waited out its accept deadline instead of failing as soon as the helper gave up")
	require.Contains(t, err.Error(), "failed near: route",
		"the failure reason the helper sent has to reach the caller: it is what the tray notification shows")
}

// TestReceiveFdReportsAGiveUpWithoutReason 覆盖不带原因的 helper：仅凭这次连接本身
// 也必须让启动失败，而不是等一个永远不会到来的 fd。
func TestReceiveFdReportsAGiveUpWithoutReason(t *testing.T) {
	socketPath := fdTestSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint:errcheck

	notified := make(chan struct{})
	go func() {
		defer close(notified)
		notifyStartFailure(socketPath, nil)
	}()

	_, err = ReceiveFd(listener)
	<-notified

	require.Error(t, err, "a helper that gave up without a reason still did not start")
}

// TestFailurePayload 保证失败文本能直接用于桌面通知：始终一行，且不超过父进程读取的
// socket 消息长度。
func TestFailurePayload(t *testing.T) {
	require.Nil(t, failurePayload(nil), "a helper without a reason sends nothing")

	payload := string(failurePayload(errors.New("run create script: \n  \"bash /tmp/x.sh\":\texit status 1\n")))
	require.Equal(t, `run create script: "bash /tmp/x.sh": exit status 1`, payload)

	// 截断时两端都要留：开头是失败的步骤，结尾是脚本自己的 "failed near:" 摘要。
	long := string(failurePayload(errors.New("start of the reason " +
		strings.Repeat("x", 4*maxHelperFailureReason) + " failed near: route")))
	require.Len(t, long, maxHelperFailureReason, "the parent reads exactly one message of this size")
	require.True(t, strings.HasPrefix(long, "start of the reason"), "the front has to survive: %q", long)
	require.True(t, strings.HasSuffix(long, "failed near: route"), "the summary at the back has to survive: %q", long)
	require.Contains(t, long, " ... ")
}

// TestHelperFailureReasonCarriesTheScriptDiagnostics 守住托盘通知带的是脚本自身的诊断
// （失败步骤 + "failed near:" 摘要）而不只是 "exit status 1"；stub 工具同时保证测试不改写本机网络。
func TestHelperFailureReasonCarriesTheScriptDiagnostics(t *testing.T) {
	shell, tools := "bash", []string{"ip"}
	if runtime.GOOS == "darwin" {
		shell, tools = "sh", []string{"ifconfig", "route"}
	}
	if _, err := exec.LookPath(shell); err != nil {
		t.Skipf("%s is unavailable in this environment: %v", shell, err)
	}

	dir := t.TempDir()
	for _, tool := range tools {
		stub := "#!/bin/sh\necho 'stub tool rejects the call' 1>&2\nexit 1\n"
		require.NoError(t, os.WriteFile(filepath.Join(dir, tool), []byte(stub), 0o755))
	}

	origPath := os.Getenv("PATH")
	require.NoError(t, os.Setenv("PATH", dir+string(os.PathListSeparator)+origPath))
	t.Cleanup(func() { _ = os.Setenv("PATH", origPath) })

	err := runCreateScript("tun-easyss-test", tun.NewScriptArgs(tun.DeviceConfig{
		Device:       "tun-easyss-test",
		TunIP:        "198.18.0.1",
		TunGW:        "198.18.0.1",
		TunMask:      "255.255.0.0",
		LocalGateway: "192.168.3.1",
	}, "", 1500))
	require.Error(t, err, "every stubbed tool rejects its call: the script has to report that")

	reason := string(failurePayload(fmt.Errorf("run create script: %w", err)))
	require.Contains(t, reason, "stub tool rejects the call", "the reason has to carry what the script reported")
	require.Contains(t, reason, "failed near:", "the script's summary is the part the user acts on")
	require.Equal(t, 1, strings.Count(reason, "create script"),
		"only giveUp names the step: the error it wraps must not repeat it: %q", reason)
	require.NotContains(t, reason, "\n", "a notification cannot render the script's newlines")
	require.LessOrEqual(t, len(reason), maxHelperFailureReason)
}

// TestReceiveFdReceivesTheSentFd 从另一侧守护同一条路径：放弃信号不能让父进程拒绝
// 健康 helper 发来的 fd。
func TestReceiveFdReceivesTheSentFd(t *testing.T) {
	socketPath := fdTestSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint:errcheck

	pipeReader, pipeWriter, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		pipeReader.Close() //nolint:errcheck
		pipeWriter.Close() //nolint:errcheck
	})

	sent := make(chan error, 1)
	go func() { sent <- sendFdToParent(socketPath, int(pipeReader.Fd())) }()

	fd, err := ReceiveFd(listener)
	require.NoError(t, err)
	require.NoError(t, <-sent, "the helper failed to send its fd")

	// 收到的必须是 helper 发出的管道读端，而不只是某个数字。
	received := os.NewFile(uintptr(fd), "received-fd")
	t.Cleanup(func() { received.Close() }) //nolint:errcheck

	_, err = pipeWriter.Write([]byte("tun"))
	require.NoError(t, err)
	buf := make([]byte, 3)
	_, err = io.ReadFull(received, buf)
	require.NoError(t, err)
	require.Equal(t, "tun", string(buf))
}

// TestRouteFieldsContain 固定残留判定的精确性：按空白分词后整对比较字段。子串匹配
// 会让 "dev tun" 命中 "dev tun0"，把别的设备误判成残留并触发多余的提权回滚。
func TestRouteFieldsContain(t *testing.T) {
	darwinUp := "   route to: 1.1.1.1\ndestination: 1.0.0.0\n       mask: 255.0.0.0\n    gateway: 198.18.0.1\n  interface: utun9\n"
	darwinClean := "   route to: 1.1.1.1\ndestination: 0.0.0.0\n       mask: 0.0.0.0\n    gateway: 192.168.3.1\n  interface: en0\n"
	linuxUp := "1.1.1.1 dev tun-easyss src 198.18.0.1 uid 501"
	linuxClean := "1.1.1.1 via 192.168.3.1 dev en0 src 192.168.3.20 uid 501"

	for _, tc := range []struct {
		name  string
		out   string
		key   string
		value string
		want  bool
	}{
		{"darwin: our gateway", darwinUp, "gateway:", "198.18.0.1", true},
		{"darwin: physical gateway", darwinClean, "gateway:", "198.18.0.1", false},
		{"darwin: our interface", darwinUp, "interface:", "utun9", true},
		{"darwin: gateway is a prefix of another address", "    gateway: 198.18.0.11\n", "gateway:", "198.18.0.1", false},
		{"linux: our device", linuxUp, "dev", "tun-easyss", true},
		{"linux: physical device", linuxClean, "dev", "tun-easyss", false},
		{"linux: device name is a prefix of another device", "1.1.1.1 dev tun0 src 198.18.0.1", "dev", "tun", false},
		{"missing value", "nothing here", "dev", "tun0", false},
		{"empty output", "", "dev", "tun0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, routeFieldsContain(tc.out, tc.key, tc.value))
		})
	}
}

// stubRouteProbe 返回固定输出的路由查询函数与调用记录：残留判定只看这份文本里的
// 字段，不需要真实的系统路由表。
func stubRouteProbe(out string) (func(string, ...string) (string, error), *[][]string) {
	var calls [][]string
	run := func(name string, args ...string) (string, error) {
		calls = append(calls, append([]string{name}, args...))
		return out, nil
	}
	return run, &calls
}

// TestHelperAndDirectPathsShareTheScriptArgs 钉住两条启用路径都只经过 tun.ScriptArgs：
// 否则 helper 会把裸地址传给 linux 脚本，同一次会话装出 /32 与 /16 两种路由，偏差永远不报错。
func TestHelperAndDirectPathsShareTheScriptArgs(t *testing.T) {
	cfg := &proxy.TunConfig{
		Device:         "tun-easyss-test",
		TunIP:          "198.18.0.1",
		TunGW:          "198.18.0.1",
		TunMask:        "255.255.0.0",
		TunIPV6Sub:     "2001:0db8:0:f101::1/64",
		TunGWV6:        "fe80::1",
		ServerIPV6:     "2001:db8::2",
		LocalGateway:   "192.168.3.1",
		LocalGatewayV6: "fe80::2",
		DNSAddr:        "127.0.0.1:5353",
		MTU:            1500,
	}

	// 直连路径：Manager 从同一份配置构造的实参。第 8 位（适配器 DNS）在两条路径上都是空：
	// windows 的脚本从 cmd/easyss 拿 DNS，darwin/linux 的 helper 自己用 DNSAddr 调
	// util.SetSysDNSForTun，脚本没有这个位置参数。
	direct := tun.NewScriptArgs(tun.DeviceConfig{
		Device:         cfg.Device,
		TunIP:          cfg.TunIP,
		TunGW:          cfg.TunGW,
		TunMask:        cfg.TunMask,
		TunIPV6Sub:     cfg.TunIPV6Sub,
		TunGWV6:        cfg.TunGWV6,
		ServerIPV6:     cfg.ServerIPV6,
		LocalGateway:   cfg.LocalGateway,
		LocalGatewayV6: cfg.LocalGatewayV6,
	}, "", cfg.MTU)

	viaHelper := scriptArgsFor(cfg)

	// 逐平台比较而非只比本机：掩码只出现在 linux 布局里，任何主机上都要抓得住分叉。
	for _, platform := range []tun.ScriptPlatform{
		tun.PlatformLinux, tun.PlatformDarwin, tun.PlatformWindows,
	} {
		require.Equal(t, direct.CreateFor(platform), viaHelper.CreateFor(platform),
			"%s: the helper must hand the create script the same positional arguments as the direct path",
			platform)
		require.Equal(t, direct.CloseFor(platform), viaHelper.CloseFor(platform),
			"%s: the helper must hand the close script the same positional arguments as the direct path",
			platform)
	}

	require.Equal(t, "198.18.0.1/255.255.0.0", viaHelper.CreateFor(tun.PlatformLinux)[1],
		"linux 的地址位必须带掩码：裸地址会装成 /32 直连路由")
}
