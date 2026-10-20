package tun

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nange/easyss/v3/scripts"
	"github.com/stretchr/testify/require"
)

// errCreateFailed 是平台脚本拒绝命令、以非零退出码结束时的报错。
var errCreateFailed = errors.New("tun: exec create script: exit status 1")

// TestCloseTunDevRunsTheCloseScript 钉住创建脚本失败后的路由回滚：Start() 必须删掉脚本
// 在失败前可能已装上的路由，否则 Stop() 会因 m.running 仍为 false 提前返回，残留路由把
// 每个包送进无人读取的设备，TUN 流量死循环。关闭脚本换成记录参数的桩。
func TestCloseTunDevRunsTheCloseScript(t *testing.T) {
	require.NotNil(t, scripts.CloseTunBytes, "this test needs the platform close script to be embedded")

	// 非 root 时会经 pkexec 运行关闭脚本，而 CI 没有 polkit 代理应答授权提示。
	if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && os.Geteuid() != 0 {
		t.Skip("running the close script needs root on unix")
	}

	origBytes, origName := scripts.CloseTunBytes, scripts.CloseTunFilename
	t.Cleanup(func() { scripts.CloseTunBytes, scripts.CloseTunFilename = origBytes, origName })

	marker := filepath.Join(t.TempDir(), "close-ran")
	scripts.CloseTunFilename = closeScriptName()
	scripts.CloseTunBytes = []byte(markerScript(marker))

	m := New(Config{
		Socks5Addr: "socks5://127.0.0.1:1",
		Device:     "tun-easyss-test",
		TunIP:      "198.18.0.1",
		TunGW:      "198.18.0.1",
		TunMask:    "255.255.0.0",
		TunIPV6Sub: "2001:db8::1/64",
	})

	require.NoError(t, m.closeTunDevAndDelIPRoute())
	content, err := os.ReadFile(marker)
	require.NoError(t, err, "the close script did not run: the routes of a failed TUN start would stay behind")
	require.Contains(t, string(content), "tun-easyss-test")
	if runtime.GOOS == "windows" {
		// 第三个参数必须是裸 v6 地址：netsh delete address 只接受纯地址，而持久化
		// v6 地址仍在适配器上时创建脚本的 "add address" 会失败。
		require.Contains(t, string(content), "2001:db8::1")
		require.NotContains(t, string(content), "/64")
	}
}

// TestStartRollbackAfterCreateFailure 守住回滚顺序"停引擎 → 跑关闭脚本 → 恢复系统 DNS"：
// 漏掉 DNS 恢复会把系统 DNS 一直指向 TUN 解析器。
func TestStartRollbackAfterCreateFailure(t *testing.T) {
	t.Parallel()

	var order []string

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
	stubStartHooks(m)
	m.plat.saveDNS = func(m *Manager) error {
		order = append(order, "save-dns")
		// 这是 saveAndSetDNSStep 在改动系统 DNS 后记录的内容。
		m.originDNS = []string{"192.168.1.1"}
		m.dnsChanged = true
		return nil
	}
	m.plat.createDev = func(*Manager) error {
		order = append(order, "create")
		return errCreateFailed
	}
	m.plat.closeDev = func(*Manager) error {
		order = append(order, "close")
		return nil
	}
	m.plat.restoreDNS = func(m *Manager) error {
		order = append(order, "restore-dns")
		require.True(t, m.dnsChanged,
			"the failure path must restore the DNS it changed, and dnsChanged is what restoreDNSStep acts on")
		return nil
	}

	// Windows 由脚本配置适配器 DNS，从不改动系统 DNS，故失败路径没有 DNS 步骤。
	want := []string{"create", "close"}
	if manageSystemDNS() {
		want = []string{"save-dns", "create", "close", "restore-dns"}
	}

	err := m.Start()
	require.Error(t, err, "a failed create script must fail the start")
	require.Contains(t, err.Error(), "create device", "the error has to name the failed step so the tray can report it")
	require.False(t, m.IsRunning(), "a failed start must not report a running tunnel")

	require.Equal(t, want, order,
		"the failure path has to stop the engine, delete the routes the script may have installed, and put the system DNS back")
}

// TestStartRollbackSkipsUntouchedDNS 守住 DNS 回滚的另一半：没改过系统 DNS 的启动
// 不得把它写回去，darwin 上恢复 "empty" 会清空 DHCP 提供的 DNS 服务器。
func TestStartRollbackSkipsUntouchedDNS(t *testing.T) {
	t.Parallel()

	if !manageSystemDNS() {
		t.Skip("this platform does not switch the system DNS for TUN")
	}

	var restoreCalled bool

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
	stubStartHooks(m)
	m.plat.saveDNS = func(m *Manager) error {
		// darwin 手工配置了 DNS：dnsChanged 为 false，无需恢复。
		m.originDNS = []string{"192.168.1.1"}
		m.dnsChanged = false
		return nil
	}
	m.plat.createDev = func(*Manager) error { return errCreateFailed }
	m.plat.restoreDNS = func(*Manager) error {
		restoreCalled = true
		return nil
	}
	require.Error(t, m.Start())

	require.True(t, restoreCalled, "the failure path calls the restore step")
	require.False(t, m.dnsChanged, "a start that did not change the system DNS must not have it restored")
}

// TestStartCreateScriptFailureEndToEnd 端到端跑真实脚本管道：失败必须以指明步骤的错误从
// Start() 返回且仍运行关闭脚本。非 root 会卡在提权提示上，故只留给 root 环境。
func TestStartCreateScriptFailureEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the replacement scripts are POSIX shell scripts; cmd.exe is covered by tun_script_windows_test.go")
	}
	if os.Geteuid() != 0 {
		t.Skip("the create script runs through pkexec/osascript without root, which a test runner cannot authorize")
	}

	origCreateBytes, origCreateName := scripts.CreateTunBytes, scripts.CreateTunFilename
	origCloseBytes, origCloseName := scripts.CloseTunBytes, scripts.CloseTunFilename
	t.Cleanup(func() {
		scripts.CreateTunBytes, scripts.CreateTunFilename = origCreateBytes, origCreateName
		scripts.CloseTunBytes, scripts.CloseTunFilename = origCloseBytes, origCloseName
	})

	dir := t.TempDir()
	createRan := filepath.Join(dir, "create-ran")
	closeRan := filepath.Join(dir, "close-ran")
	scripts.CreateTunFilename = "create_tun_dev_test.sh"
	scripts.CreateTunBytes = []byte("#!/bin/sh\necho ran > \"" + createRan + "\"\nexit 1\n")
	scripts.CloseTunFilename = "close_tun_dev_test.sh"
	scripts.CloseTunBytes = []byte("#!/bin/sh\necho ran > \"" + closeRan + "\"\n")

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
	stubStartHooks(m)
	// 这里必须是真实实现：本测试验证的正是写脚本、经平台解释器运行、读回退出码这条管道。
	m.plat.createDev = func(m *Manager) error { return m.createTunDevAndSetIPRoute() }
	m.plat.closeDev = func(m *Manager) error { return m.closeTunDevAndDelIPRoute() }
	err := m.Start()
	require.Error(t, err, "the create script exited 1: Start must not report a running tunnel")
	require.Contains(t, err.Error(), "create device")

	_, statErr := os.Stat(createRan)
	require.NoError(t, statErr, "the create script did not run")
	_, statErr = os.Stat(closeRan)
	require.NoError(t, statErr, "the close script did not run: the routes of the failed start would stay behind")
}

// stubStartHooks 用空操作替换引擎、就绪停顿、DNS 步骤与平台脚本：不真正启动
// tun2socks（要打开 TUN 设备、需要 root）。需要钩子做事的测试在本函数之后再赋值。
func stubStartHooks(m *Manager) {
	m.plat.engineStart = func() error { return nil }
	m.plat.engineStop = func(string) {}
	m.plat.settle = func() {}
	m.plat.saveDNS = func(*Manager) error { return nil }
	m.plat.restoreDNS = func(*Manager) error { return nil }
	m.plat.createDev = func(*Manager) error { return nil }
	m.plat.closeDev = func(*Manager) error { return nil }
}

// closeScriptName 返回按平台分支交给解释器执行的关闭脚本名。
func closeScriptName() string {
	if runtime.GOOS == "windows" {
		return "close_tun_dev_rollback_test.bat"
	}
	return "close_tun_dev_rollback_test.sh"
}

// markerScript 返回用当前平台语言编写的脚本，把参数写入 marker。
func markerScript(marker string) string {
	if runtime.GOOS == "windows" {
		return "@echo off\r\necho %* > \"" + marker + "\"\r\nexit /b 0\r\n"
	}
	return "#!/bin/sh\necho \"$@\" > \"" + marker + "\"\n"
}
