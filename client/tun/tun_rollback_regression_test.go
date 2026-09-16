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

// errCreateFailed 是桩（stub）化创建脚本上报的错误：平台脚本
// 拒绝了命令并以非零退出码结束，这是 unix 和 Windows
// 创建脚本现在实现的约定。
var errCreateFailed = errors.New("tun: exec create script: exit status 1")

// TestCloseTunDevRunsTheCloseScript 将回滚行为固定下来，
// 防止出现 TUN 流量死循环：当创建脚本失败时，Start()
// 必须删除脚本在失败前可能已经安装的路由。
//
// 在此之前该路径上只会运行 stopEngine。随后托盘调用 Stop()，
// 而 Stop() 会因 m.running 仍为 false 而提前返回，
// 于是路由残留在系统路由表中，把每个数据包
// 都送入一个无人读取的 TUN 设备。
//
// 回滚通过 Start() 调用的同一个辅助函数来触发，
// 只是把关闭脚本替换为把参数记录到标记文件中的脚本：
// 真正删除路由需要管理员权限，
// 并且会改写机器的网络配置；
// 这里要证明的是清理逻辑确实会运行，
// 并且带着平台脚本所需的参数运行。
// 平台关闭脚本本身由辅助测试覆盖。
func TestCloseTunDevRunsTheCloseScript(t *testing.T) {
	require.NotNil(t, scripts.CloseTunBytes, "this test needs the platform close script to be embedded")

	// unix 上除非测试本身已是 root，否则会通过 pkexec 运行关闭脚本，
	// 而 CI 运行环境没有 polkit 代理来应答必然弹出的授权提示。
	// 在那里运行本检查测试的是提权逻辑，
	// 而不是回滚。
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
		// 第三个参数是裸的 v6 地址（不带 /64）：
		// netsh delete address 接受纯地址，而在持久化 v6 地址
		// 仍位于适配器上时，创建脚本的 "add address"
		// 无法重新应用它。
		require.Contains(t, string(content), "2001:db8::1")
		require.NotContains(t, string(content), "/64")
	}
}

// TestStartRollbackAfterCreateFailure 通过包级钩子驱动完整的
// Start() 失败路径：创建脚本以非零退出码结束（这正是平台脚本
// 现在的行为，参见 create_tun_dev.sh、create_tun_dev_darwin.sh
// 和 create_tun_dev_windows.bat 中的退出码约定），
// 而 Start() 必须撤销它已经做过的一切。
//
// 它是 TestCloseTunDevRunsTheCloseScript 的跨平台对应物：
// 那个测试证明关闭脚本在其运行的平台上以正确的参数被调用，
// 这个测试证明回滚确实会发生、顺序正确，
// 并且包含系统 DNS —— 同样的失败过去会让系统 DNS
// 一直指向 TUN 解析器。它用钩子替换了引擎、脚本和 DNS 设置，
// 因为真实的实现需要 TUN 设备、管理员权限和活动的代理 ——
// 而且会重配置运行测试的机器的网络。
func TestStartRollbackAfterCreateFailure(t *testing.T) {
	var order []string

	stubStartHooks(t)
	saveAndSetDNSStepFn = func(m *Manager) error {
		order = append(order, "save-dns")
		// 这是 saveAndSetDNSStep 在改动系统 DNS 后记录的内容。
		m.originDNS = []string{"192.168.1.1"}
		m.dnsChanged = true
		return nil
	}
	createTunDevFn = func(*Manager) error {
		order = append(order, "create")
		return errCreateFailed
	}
	closeTunDevFn = func(*Manager) error {
		order = append(order, "close")
		return nil
	}
	restoreDNSStepFn = func(m *Manager) error {
		order = append(order, "restore-dns")
		require.True(t, m.dnsChanged,
			"the failure path must restore the DNS it changed, and dnsChanged is what restoreDNSStep acts on")
		return nil
	}

	// Windows 由自己的脚本配置适配器 DNS，从不改动系统 DNS，
	// 因此其失败路径没有需要运行的 DNS 步骤。
	want := []string{"create", "close"}
	if manageSystemDNS() {
		want = []string{"save-dns", "create", "close", "restore-dns"}
	}

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})

	err := m.Start()
	require.Error(t, err, "a failed create script must fail the start")
	require.Contains(t, err.Error(), "create device", "the error has to name the failed step so the tray can report it")
	require.False(t, m.IsRunning(), "a failed start must not report a running tunnel")

	require.Equal(t, want, order,
		"the failure path has to stop the engine, delete the routes the script may have installed, and put the system DNS back")
}

// TestStartRollbackSkipsUntouchedDNS 是 DNS 回滚的另一半：
// 从未重配置过系统 DNS 的启动过程不得把它写回去。
// 在 darwin 上，未改动过的系统会被恢复为 "empty"，
// 这会清空 DHCP 提供的服务器，而不是让它们保持原样。
func TestStartRollbackSkipsUntouchedDNS(t *testing.T) {
	if !manageSystemDNS() {
		t.Skip("this platform does not switch the system DNS for TUN")
	}

	var restoreCalled bool

	stubStartHooks(t)
	saveAndSetDNSStepFn = func(m *Manager) error {
		// darwin 且手工配置了 DNS：没有任何改动，
		// 因此也无需恢复。
		m.originDNS = []string{"192.168.1.1"}
		m.dnsChanged = false
		return nil
	}
	createTunDevFn = func(*Manager) error { return errCreateFailed }
	closeTunDevFn = func(*Manager) error { return nil }
	restoreDNSStepFn = func(*Manager) error {
		restoreCalled = true
		return nil
	}

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
	require.Error(t, m.Start())

	require.True(t, restoreCalled, "the failure path calls the restore step")
	require.False(t, m.dnsChanged, "a start that did not change the system DNS must not have it restored")
}

// TestStartCreateScriptFailureEndToEnd 端到端走一遍真实的脚本管道：
// 把内嵌的创建脚本替换为会失败的脚本，
// 失败必须以指明步骤的错误从 Start() 中返回，
// 并且之后还要运行关闭脚本。
//
// 它需要借助平台所用的解释器运行脚本，而在非 root 情况下，
// linux 上是通过 pkexec、darwin 上是通过
// "osascript ... with administrator privileges"：测试运行环境
// 既没有 polkit 代理，也没有可应答的授权对话框，
// 因此脚本根本不会运行（darwin 上还会白白耗掉
// 60 秒的创建超时和 30 秒的关闭超时）。退出码约定
// 本身在非 root 情况下由 cmd/easyss/tun_script_unix_test.go
// 覆盖，cmd.exe 由 tun_script_windows_test.go 覆盖，
// 因此这个端到端检查留给已经以 root 运行的环境。
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

	stubStartHooks(t)
	// 这里必须运行真实实现：本测试要验证的是脚本管道
	// （写出内嵌脚本、通过平台解释器运行、读回其退出码），
	// 这正是上面那个失败的桩所替换掉的部分。
	// 绝不能是空操作。
	createTunDevFn = func(m *Manager) error { return m.createTunDevAndSetIPRoute() }
	closeTunDevFn = func(m *Manager) error { return m.closeTunDevAndDelIPRoute() }

	m := New(Config{Socks5Addr: "socks5://127.0.0.1:1", Device: "tun-easyss-test"})
	err := m.Start()
	require.Error(t, err, "the create script exited 1: Start must not report a running tunnel")
	require.Contains(t, err.Error(), "create device")

	_, statErr := os.Stat(createRan)
	require.NoError(t, statErr, "the create script did not run")
	_, statErr = os.Stat(closeRan)
	require.NoError(t, statErr, "the close script did not run: the routes of the failed start would stay behind")
}

// stubStartHooks 用空操作钩子替换引擎、就绪停顿、DNS 步骤
// 和平台脚本，并在测试结束时恢复它动过的每一个钩子。
// 它让测试不会真的启动 tun2socks（那会打开 TUN 设备
// 并需要管理员权限），也不会干等设备就绪停顿；
// 需要钩子做事的测试
// 在调用本函数之后再为钩子赋值。
func stubStartHooks(t *testing.T) {
	t.Helper()

	origStart, origStop := engineStartFn, engineStopFn
	origDelay := settleDelay
	origSave, origRestore := saveAndSetDNSStepFn, restoreDNSStepFn
	origCreate, origClose := createTunDevFn, closeTunDevFn

	engineStartFn = func() error { return nil }
	engineStopFn = func(string) {}
	settleDelay = func() {}
	saveAndSetDNSStepFn = func(*Manager) error { return nil }
	restoreDNSStepFn = func(*Manager) error { return nil }
	createTunDevFn = func(*Manager) error { return nil }
	closeTunDevFn = func(*Manager) error { return nil }

	t.Cleanup(func() {
		engineStartFn, engineStopFn = origStart, origStop
		settleDelay = origDelay
		saveAndSetDNSStepFn, restoreDNSStepFn = origSave, origRestore
		createTunDevFn, closeTunDevFn = origCreate, origClose
	})
}

// closeScriptName 返回一个关闭脚本名，供 closeTunDevAndDelIPRoute 的平台分支
// 交给其解释器执行。
func closeScriptName() string {
	if runtime.GOOS == "windows" {
		return "close_tun_dev_rollback_test.bat"
	}
	return "close_tun_dev_rollback_test.sh"
}

// markerScript 返回一个用当前运行平台的语言编写的脚本，把它的参数记录到标记
// 文件中。
func markerScript(marker string) string {
	if runtime.GOOS == "windows" {
		return "@echo off\r\necho %* > \"" + marker + "\"\r\nexit /b 0\r\n"
	}
	return "#!/bin/sh\necho \"$@\" > \"" + marker + "\"\n"
}
