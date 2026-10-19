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

// closeFailureMarker 是 close_tun_dev_windows.bat 报告真实清理失败时打印到
// stderr 的前缀：脚本的退出码只回答"路由到底删干净没有"，原因必须能从输出里
// 读出来，否则用户看到的只是一条没有下文的告警。
const closeFailureMarker = "[close_tun_dev_windows]"

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

	// stubTool 写入一个以给定码退出的工具：每次调用都把收到的命令行追加到
	// logPath，失败时另外在 stderr 打印标记。存根永远"成功"，所以仅凭退出码
	// 区分不出脚本走了哪个分支（例如 server_ip_v6 为空时不应进入 ipv6 分支），
	// 调用日志才是分支断言的数据来源。
	//
	// 记录文件路径直接写进存根脚本（与 TestCloseTunScriptCleanup 的记录存根同一
	// 做法），不依赖环境变量：cmd.exe 子进程的环境继承在这里不可靠。
	stubTool := func(t *testing.T, dir, name, logPath string, code int) {
		t.Helper()

		record := "echo %* >> \"" + logPath + "\"\r\n"
		body := "@echo off\r\n" + record + "exit /b " + strconv.Itoa(code) + "\r\n"
		if code != 0 {
			body = "@echo off\r\n" + record + "echo " + name + " failed 1>&2\r\nexit /b " + strconv.Itoa(code) + "\r\n"
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
	}

	// 带空格的路径中的存根目录会被未加引号的工具调用拆成多个参数，
	// 把本测试变成引号测试而非退出码测试。
	stubRoot := t.TempDir()
	if strings.Contains(stubRoot, " ") {
		t.Skipf("temp directory %q contains a space: the stub directory could not be reached unquoted", stubRoot)
	}

	// runScript 用 netsh 和 route 的存根运行创建脚本，返回其退出码、合并输出与
	// 存根调用日志。serverIPV6 把脚本切到 ipv6 分支，mtu 则决定脚本是否调用
	// netsh 写适配器的 MTU（空值表示调用方没给，脚本应保持适配器默认配置）。
	runScript := func(t *testing.T, netshCode, routeCode int, serverIPV6, mtu string) (int, string, string) {
		t.Helper()

		dir, err := os.MkdirTemp(stubRoot, "stubs")
		require.NoError(t, err)
		logPath := filepath.Join(dir, "calls.log")
		stubTool(t, dir, "netsh.cmd", logPath, netshCode)
		stubTool(t, dir, "route.cmd", logPath, routeCode)

		// 参数形状与 client/tun/tun.go 的 windows 分支一致：6 个设备/路由参数
		// + 第 7 个服务端 IPv6（没有时为空字符串，与生产路径相同）+ 第 8 个
		// 系统 DNS（由 cmd/easyss 的 tunDNS 计算后传入）+ 第 9 个 MTU（来自
		// local.tun_mtu，tun2socks 自己设不了 wintun 适配器的 MTU）。
		args := append([]string{"/C", script},
			"tun-easyss-test", "198.18.0.1", "198.18.0.1", "255.255.0.0",
			"2001:db8::1/64", "fe80::1", serverIPV6, "223.5.5.5", mtu)

		cmd := exec.Command(comspec, args...)
		cmd.Env = append(os.Environ(), "PATH="+dir+";"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()

		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr, "running the create script with stubbed tools: %v", err)
			code = exitErr.ExitCode()
		}
		calls, readErr := os.ReadFile(logPath)
		require.NoError(t, readErr, "the stub tools were never invoked; script output:\n%s", out)
		return code, string(out), string(calls)
	}

	t.Run("every command succeeds", func(t *testing.T) {
		code, out, calls := runScript(t, 0, 0, "", "1500")
		require.Equal(t, 0, code, "the create script must exit 0 when every command succeeds:\n%s", out)
		require.Contains(t, calls, `interface ipv4 set subinterface "tun-easyss-test" mtu=1500 store=active`,
			"the mtu passed by the caller must be applied to the adapter:\n%s", calls)
	})

	// TestCreateTunScriptBranchSelection 的回归目标：Go 把空参数编码为字面 ""，
	// cmd 会把这对引号保留在 %7 里，因此脚本必须用 %~7 去引号。否则在服务端没有
	// IPv6（或 ipv6_rule=disable）时，"%server_ip_v6%" 看起来非空，脚本会误入
	// ipv6 分支，把 v6 地址与 ::/1、8000::/1 默认路由装进一条没有服务端 IPv6
	// 承载它们的隧道。存根永远成功，只有调用日志能区分这两种分支。
	t.Run("empty server ipv6 keeps the ipv6 branch off", func(t *testing.T) {
		code, out, calls := runScript(t, 0, 0, "", "1500")
		require.Equal(t, 0, code, "%s", out)
		require.Contains(t, calls, "set dns name=tun-easyss-test static 223.5.5.5",
			"the dns passed by the caller must be applied:\n%s", calls)
		require.NotContains(t, calls, "ipv6",
			"an empty server ipv6 (Go passes it as a literal \"\") must not install ipv6 routes:\n%s", calls)
	})

	t.Run("empty mtu keeps the adapter default", func(t *testing.T) {
		// 调用方没有给 MTU（例如老版本布局）时不得凭空写一个值进去：
		// 半配置的适配器 MTU 与 netstack 的 MTU 不一致时只会静默丢包。
		code, out, calls := runScript(t, 0, 0, "", "")
		require.Equal(t, 0, code, "%s", out)
		require.NotContains(t, calls, "set subinterface",
			"an empty mtu must leave the adapter configuration alone:\n%s", calls)
	})

	t.Run("non-empty server ipv6 installs the ipv6 routes", func(t *testing.T) {
		code, out, calls := runScript(t, 0, 0, "2001:db8::2", "1500")
		require.Equal(t, 0, code, "%s", out)
		require.Contains(t, calls, "ipv6 add route ::/1",
			"a server ipv6 must install the ipv6 default routes:\n%s", calls)
		require.Contains(t, calls, `interface ipv6 set subinterface "tun-easyss-test" mtu=1500 store=active`,
			"an ipv6-carrying tunnel needs the ipv6 mtu too:\n%s", calls)
	})

	t.Run("failing netsh fails the script", func(t *testing.T) {
		// 地址与 DNS 命令失败而路由被安装：这正是过去看起来像成功启动的情形。
		code, out, _ := runScript(t, 9009, 0, "", "1500")
		require.NotEqualf(t, 0, code, "a failing netsh must not leave the script with a zero exit code:\n%s", out)
		require.Contains(t, out, failureMarker,
			"the failing step must be reported on stderr so the tray notification can show it")
	})

	t.Run("failing route fails the script", func(t *testing.T) {
		code, out, _ := runScript(t, 0, 1, "", "1500")
		require.NotEqualf(t, 0, code, "a failing route add must not leave the script with a zero exit code:\n%s", out)
		require.Contains(t, out, failureMarker,
			"the failing step must be reported on stderr so the tray notification can show it")
	})

	t.Run("failing command in the ipv6 branch fails the script", func(t *testing.T) {
		// 这里只有 ipv6 块可能失败，意味着 ipv4 地址与路由已先安装：
		// 正是 Manager.Start 必须回滚的部分配置设备。
		code, out, _ := runScript(t, 9009, 0, "2001:db8::2", "1500")
		require.NotEqualf(t, 0, code, "an ipv6 command failure must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, failureMarker)

		code, out, _ = runScript(t, 0, 0, "2001:db8::2", "1500")
		require.Equal(t, 0, code, "the ipv6 branch must not fail when every command succeeds:\n%s", out)
	})
}

// closeScriptStub 描述关闭脚本两条查询命令的存根回答。
type closeScriptStub struct {
	// probeCode 是 netsh "show interface" 的退出码：0 = 接口还在，1 = 接口未注册
	// （引擎停止时 wintun 适配器已经被注销，挂在它上面的路由与 v6 地址同时被
	// 系统收走——这正是正常关闭的形态），9009 = netsh 本身跑不起来。
	probeCode int
	// tableRows 是 route 的 "print -4" 要回放的路由表行；为空表示回放一张空表。
	tableRows []string
}

// TestCloseTunScriptCleanup 用记录存根运行真实的关闭脚本，并钉住它的两条契约：
//
//   - 必须发出的命令：创建脚本安装的同一路由阶梯（相同目的与掩码）、两条 ipv6
//     路由，以及 ipv6 地址——netsh add address 是持久的，创建脚本的无条件
//     "add address" 无法在地址仍在适配器上时重新应用，因此关闭脚本必须删除它
//     （/prefix 处理见 client/tun/script_args.go 的 ScriptArgs）。
//   - 退出码：设备已经不存在时不得报失败，而路由真的残留下来时必须以非零码退出
//     ——残留的分流默认路由会把全机 IPv4 流量送进一个没人读的 TUN 设备。
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

	// runClose 用 netsh/route 存根运行关闭脚本，返回退出码、合并输出与记录下来的
	// 命令行。存根按 closeScriptStub 回答脚本的两条查询命令：接口是否还在
	// （netsh show interface）与路由表的内容（route print -4，默认空表）。
	// 记录为空（脚本在探测阶段就退出）不是错误：调用方按各子用例的期望断言。
	runClose := func(t *testing.T, stub closeScriptStub, args ...string) (int, string, []string) {
		t.Helper()

		dir, err := os.MkdirTemp(stubRoot, "stubs")
		require.NoError(t, err)
		record := filepath.Join(dir, "record.txt")

		recordCall := "echo %* >> \"" + record + "\"\r\n"

		// netsh 用退出码回答"接口还在不在"：脚本正是这样判断的——它打印的文本
		// （未注册接口是 "The filename, directory name, or volume label syntax is
		// incorrect."）与真正的失败无法区分，而且随系统语言变化。
		netshBody := "@echo off\r\n" + recordCall +
			"if \"%1\"==\"interface\" if \"%2\"==\"show\" exit /b " + strconv.Itoa(stub.probeCode) + "\r\n" +
			"exit /b 0\r\n"
		require.NoError(t, os.WriteFile(filepath.Join(dir, "netsh.cmd"), []byte(netshBody), 0o644))

		// 回放的表行由各子用例给出（网关列用 198.18.0.1，与脚本里的残留探测
		// "tokens=1,2,3" 的第 1、3 列一致）。
		routeBody := "@echo off\r\n" + recordCall
		if len(stub.tableRows) > 0 {
			routeBody += "if \"%1\"==\"print\" (\r\n"
			for _, row := range stub.tableRows {
				routeBody += "  echo " + row + "\r\n"
			}
			routeBody += ")\r\n"
		}
		routeBody += "exit /b 0\r\n"
		require.NoError(t, os.WriteFile(filepath.Join(dir, "route.cmd"), []byte(routeBody), 0o644))

		cmd := exec.Command(comspec, append([]string{"/C", script}, args...)...)
		cmd.Env = append(os.Environ(), "PATH="+dir+";"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()

		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr, "running the close script with stubbed tools: %v\n%s", err, out)
			code = exitErr.ExitCode()
		}

		content, readErr := os.ReadFile(record)
		if readErr != nil {
			require.ErrorIs(t, readErr, os.ErrNotExist,
				"reading the stub call log; script output:\n%s", out)
			return code, string(out), nil
		}
		var lines []string
		for line := range strings.SplitSeq(string(content), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				lines = append(lines, line)
			}
		}
		return code, string(out), lines
	}

	// 正常关闭：引擎先停，wintun 适配器随之注销，路由与 v6 地址也一起消失。
	// 这是 client/tun/tun.go 的 Stop() 顺序（linux/darwin 同），因此它不是失败：
	// 过去这里会把十一条"对象已不存在"的删除报成 [TUN] close script 告警。
	t.Run("a device that is already gone is not a failure", func(t *testing.T) {
		code, out, lines := runClose(t, closeScriptStub{probeCode: 1},
			"tun-easyss-test", "198.18.0.1", "2001:db8::1")

		require.Equal(t, 0, code,
			"an adapter that is already unregistered must not be reported as a cleanup failure:\n%s", out)
		require.NotContains(t, out, closeFailureMarker, "nothing was left to clean up")
		require.Len(t, lines, 1, "only the interface probe may run when the device is gone:\n%v", lines)
		require.Contains(t, lines[0], "show interface")
	})

	// 守卫只认"接口未注册"（netsh 恰好返回 1）：netsh 自己跑不起来（9009，例如
	// 环境异常）时必须照常执行删除与残留探测，否则真正残留下来的路由会被
	// "设备已消失"这个结论掩盖掉。
	t.Run("a netsh that cannot run does not skip the cleanup", func(t *testing.T) {
		code, out, lines := runClose(t, closeScriptStub{probeCode: 9009}, "tun-easyss-test", "198.18.0.1")

		require.Equal(t, 0, code, "an empty route table is a clean table:\n%s", out)
		require.Contains(t, lines, "delete 1.0.0.0 mask 255.0.0.0 198.18.0.1",
			"the deletions must run when the probe could not answer:\n%v", lines)
		require.Contains(t, lines, "print -4", "the residue probe must run too:\n%v", lines)
	})

	t.Run("with a v6 address", func(t *testing.T) {
		code, out, lines := runClose(t, closeScriptStub{}, "tun-easyss-test", "198.18.0.1", "2001:db8::1")
		require.Equal(t, 0, code, "%s", out)

		expected := []string{
			`interface show interface name="tun-easyss-test"`,
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
			"print -4",
		}
		require.Equal(t, expected, lines)
	})

	t.Run("without a v6 address", func(t *testing.T) {
		code, out, lines := runClose(t, closeScriptStub{}, "tun-easyss-test", "198.18.0.1")
		require.Equal(t, 0, code, "%s", out)
		require.Len(t, lines, 12, "the device probe, the ten route deletions, the residue probe")
		for _, line := range lines {
			require.NotContains(t, line, "delete address")
		}
	})

	// 删除被真正拒绝（而不是"对象本来就不存在"）时路由会留在表里：那正是
	// "停止 TUN 后断网"的成因，脚本必须据此以非零码退出并说明原因。
	t.Run("residual routes fail the script", func(t *testing.T) {
		code, out, _ := runClose(t, closeScriptStub{tableRows: []string{
			"Network Destination        Netmask          Gateway       Interface  Metric",
			"          1.0.0.0        255.0.0.0      198.18.0.1      198.18.0.1      5",
		}}, "tun-easyss-test", "198.18.0.1")

		require.NotEqualf(t, 0, code, "a split route that survived the deletes must not exit 0:\n%s", out)
		require.Contains(t, out, closeFailureMarker)
	})

	// 反过来：表里"以 TUN 网关为网关"的路由并不都是本脚本装的。创建脚本的
	// "set address ... gateway" 会让适配器自己带一条默认路由（Windows 把它作为
	// 持久路由留在表里，实测），别的 VPN 客户端也可能装上 0/1、128/1 这类大段路由。
	// 它们不在本脚本删过的那 8 条里：算成残留只会让每次关闭都告警，而那 8 条其实
	// 已经删干净了。
	t.Run("routes the script never installed are not residue", func(t *testing.T) {
		code, out, _ := runClose(t, closeScriptStub{tableRows: []string{
			"Network Destination        Netmask          Gateway       Interface  Metric",
			"          0.0.0.0          0.0.0.0       198.18.0.1       198.18.0.1      1",
			"       198.18.0.0      255.255.0.0         On-link        198.18.0.1    261",
		}}, "tun-easyss-test", "198.18.0.1")

		require.Equal(t, 0, code, "a route the close script never installs is not residue:\n%s", out)
		require.NotContains(t, out, closeFailureMarker)
	})

	// 网关缺失时既不能删除也不能探测：空网关会让 route delete 丢掉网关参数
	// （可能删掉物理链路上的同名路由），并让残留探测匹配上每一行无法解析的表项。
	t.Run("a missing gateway is refused", func(t *testing.T) {
		code, out, _ := runClose(t, closeScriptStub{}, "tun-easyss-test")

		require.NotEqualf(t, 0, code, "a missing tun gateway must not be treated as success:\n%s", out)
		require.Contains(t, out, closeFailureMarker)
	})
}
