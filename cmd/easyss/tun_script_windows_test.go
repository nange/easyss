//go:build windows && !headless

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/scripts"
	"github.com/stretchr/testify/require"
)

// failureMarker 是 create_tun_dev_windows.bat 在 TUN 配置脚本的某个命令
// 失败时打印到 stderr 的内容（因此也是用户通知所显示的内容）。
const failureMarker = "[create_tun_dev_windows] failed near:"

// TestCreateTunScriptExitCode 是 Windows 上"静默成功的创建脚本造成 TUN
// 流量回路"问题的回归测试。
//
// 即使批处理内部的命令失败，cmd.exe 对没有显式 "exit /b" 的批处理文件
// 也返回 0，因此 netsh/route 命令被拒绝的脚本仍会报告成功：客户端保留
// 已安装的 TUN 路由、把 tun2socks 标记为已启动且不通知任何内容，而每个
// 数据包都进入一个既无地址也无 DNS 的设备。脚本现在会记录失败的步骤并
// 以非零码退出，这正是本测试要钉住的行为。
//
// 真实脚本像 client/tun/tun.go 那样通过 cmd.exe 运行，并在 PATH 前面
// 加一个存根工具目录，使失败可复现：netsh 拒绝配置不存在的适配器，
// 而真实安装路由需要管理员权限。存根是普通批处理文件，这可行是因为
// 脚本用 "call" 调用每个工具（见脚本中退出码契约的注释）。
func TestCreateTunScriptExitCode(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", scripts.CreateTunFilename))
	require.NoError(t, err)

	comspec := os.Getenv("COMSPEC")
	if comspec == "" {
		comspec = "cmd.exe"
	}

	// stubTool 写入一个以给定码退出的工具，失败时在 stderr 打印标记。
	stubTool := func(t *testing.T, dir, name string, code int) {
		t.Helper()

		body := "@echo off\r\nexit /b " + strconv.Itoa(code) + "\r\n"
		if code != 0 {
			body = "@echo off\r\necho " + name + " failed 1>&2\r\nexit /b " + strconv.Itoa(code) + "\r\n"
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
	}

	// 带空格的路径中的存根目录会被未加引号的工具调用拆成多个参数，
	// 把本测试变成引号测试而非退出码测试。
	stubRoot := t.TempDir()
	if strings.Contains(stubRoot, " ") {
		t.Skipf("temp directory %q contains a space: the stub directory could not be reached unquoted", stubRoot)
	}

	// runScript 用 netsh 和 route 的存根运行创建脚本，返回其退出码与
	// 合并输出。serverIPV6 把脚本切到 ipv6 分支。
	runScript := func(t *testing.T, netshCode, routeCode int, serverIPV6 string) (int, string) {
		t.Helper()

		dir, err := os.MkdirTemp(stubRoot, "stubs")
		require.NoError(t, err)
		stubTool(t, dir, "netsh.cmd", netshCode)
		stubTool(t, dir, "route.cmd", routeCode)

		args := append([]string{"/C", script},
			"tun-easyss-test", "198.18.0.1", "198.18.0.1", "255.255.0.0",
			"2001:db8::1/64", "fe80::1")
		if serverIPV6 != "" {
			args = append(args, serverIPV6)
		}

		cmd := exec.Command(comspec, args...)
		cmd.Env = append(os.Environ(), "PATH="+dir+";"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()

		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr, "running the create script with stubbed tools: %v", err)
			code = exitErr.ExitCode()
		}
		return code, string(out)
	}

	t.Run("every command succeeds", func(t *testing.T) {
		code, out := runScript(t, 0, 0, "")
		require.Equal(t, 0, code, "the create script must exit 0 when every command succeeds:\n%s", out)
	})

	t.Run("failing netsh fails the script", func(t *testing.T) {
		// 地址与 DNS 命令失败而路由被安装：这正是过去看起来像成功启动的情形。
		code, out := runScript(t, 9009, 0, "")
		require.NotEqualf(t, 0, code, "a failing netsh must not leave the script with a zero exit code:\n%s", out)
		require.Contains(t, out, failureMarker,
			"the failing step must be reported on stderr so the tray notification can show it")
	})

	t.Run("failing route fails the script", func(t *testing.T) {
		code, out := runScript(t, 0, 1, "")
		require.NotEqualf(t, 0, code, "a failing route add must not leave the script with a zero exit code:\n%s", out)
		require.Contains(t, out, failureMarker,
			"the failing step must be reported on stderr so the tray notification can show it")
	})

	t.Run("failing command in the ipv6 branch fails the script", func(t *testing.T) {
		// 这里只有 ipv6 块可能失败，意味着 ipv4 地址与路由已先安装：
		// 正是 Manager.Start 必须回滚的部分配置设备。
		code, out := runScript(t, 9009, 0, "2001:db8::2")
		require.NotEqualf(t, 0, code, "an ipv6 command failure must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, failureMarker)

		code, out = runScript(t, 0, 0, "2001:db8::2")
		require.Equal(t, 0, code, "the ipv6 branch must not fail when every command succeeds:\n%s", out)
	})
}

// TestCloseTunScriptCleanup 用记录存根运行真实的关闭脚本，并钉住它必须
// 发出的命令：创建脚本安装的同一路由阶梯（相同目的与掩码）、两条 ipv6
// 路由，以及 ipv6 地址——netsh add address 是持久的，创建脚本的无条件
// "add address" 无法在地址仍在适配器上时重新应用，因此关闭脚本必须删除它
// （/prefix 处理见 client/tun/tun.go 的 bareV6Addr）。
func TestCloseTunScriptCleanup(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", scripts.CloseTunFilename))
	require.NoError(t, err)

	comspec := os.Getenv("COMSPEC")
	if comspec == "" {
		comspec = "cmd.exe"
	}

	// 带空格的路径中的存根目录会被未加引号的工具调用拆成多个参数，
	// 把本测试变成引号测试而非命令测试。
	stubRoot := t.TempDir()
	if strings.Contains(stubRoot, " ") {
		t.Skipf("temp directory %q contains a space: the stub directory could not be reached unquoted", stubRoot)
	}

	// runClose 用把每次调用都追加到记录文件的 netsh/route 存根运行关闭
	// 脚本，并返回记录下来的命令行。
	runClose := func(t *testing.T, args ...string) []string {
		t.Helper()

		dir, err := os.MkdirTemp(stubRoot, "stubs")
		require.NoError(t, err)
		record := filepath.Join(dir, "record.txt")
		body := "@echo off\r\necho %* >> \"" + record + "\"\r\nexit /b 0\r\n"
		require.NoError(t, os.WriteFile(filepath.Join(dir, "netsh.cmd"), []byte(body), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "route.cmd"), []byte(body), 0o644))

		cmd := exec.Command(comspec, append([]string{"/C", script}, args...)...)
		cmd.Env = append(os.Environ(), "PATH="+dir+";"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "the close script must exit 0 when every stub succeeds:\n%s", out)

		content, err := os.ReadFile(record)
		require.NoError(t, err, "the stub tools were never invoked")
		var lines []string
		for line := range strings.SplitSeq(string(content), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				lines = append(lines, line)
			}
		}
		return lines
	}

	t.Run("with a v6 address", func(t *testing.T) {
		lines := runClose(t, "tun-easyss-test", "198.18.0.1", "2001:db8::1")

		expected := []string{
			"delete 1.0.0.0 mask 255.0.0.0 198.18.0.1",
			"delete 2.0.0.0 mask 254.0.0.0 198.18.0.1",
			"delete 4.0.0.0 mask 252.0.0.0 198.18.0.1",
			"delete 8.0.0.0 mask 248.0.0.0 198.18.0.1",
			"delete 16.0.0.0 mask 240.0.0.0 198.18.0.1",
			"delete 32.0.0.0 mask 224.0.0.0 198.18.0.1",
			"delete 64.0.0.0 mask 192.0.0.0 198.18.0.1",
			"delete 128.0.0.0 mask 128.0.0.0 198.18.0.1",
			"interface ipv6 delete route ::/1 tun-easyss-test",
			"interface ipv6 delete route 8000::/1 tun-easyss-test",
			"interface ipv6 delete address tun-easyss-test 2001:db8::1",
		}
		require.Equal(t, expected, lines)
	})

	t.Run("without a v6 address", func(t *testing.T) {
		lines := runClose(t, "tun-easyss-test", "198.18.0.1")
		require.Len(t, lines, 10, "only the routes are deleted")
		for _, line := range lines {
			require.NotContains(t, line, "delete address")
		}
	})
}
