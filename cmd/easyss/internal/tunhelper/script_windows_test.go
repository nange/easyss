//go:build windows && !headless

package tunhelper

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/client/tun/scripts"
	"github.com/stretchr/testify/require"
)

// create_tun_dev_windows.bat 某个命令失败时打印到 stderr 的内容。
const failureMarker = "[create_tun_dev_windows] failed near:"

// close_tun_dev_windows.bat 报告真实清理失败的前缀：退出码只回答"路由删干净没有"。
const closeFailureMarker = "[close_tun_dev_windows]"

// 防回归：cmd.exe 对没有显式 exit /b 的批处理文件也返回 0，失败的 netsh/route 会被
// 报成成功，客户端保留一条既无地址也无 DNS 的设备的路由。真实脚本通过 cmd.exe 运行，
// PATH 最前放存根工具让失败可复现（存根是批处理文件，脚本用 call 调用工具）。
func TestCreateTunScriptExitCode(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "client", "tun", "scripts", scripts.CreateTunFilename))
	require.NoError(t, err)

	comspec := os.Getenv("COMSPEC")
	if comspec == "" {
		comspec = "cmd.exe"
	}

	// 存根永远"成功"，只有记录的调用日志能区分脚本走了哪个分支。
	// 记录路径直接写进存根脚本而不依赖环境变量：cmd.exe 子进程的环境继承不可靠。
	stubTool := func(t *testing.T, dir, name, logPath string, code int) {
		t.Helper()

		record := "echo %* >> \"" + logPath + "\"\r\n"
		body := "@echo off\r\n" + record + "exit /b " + strconv.Itoa(code) + "\r\n"
		if code != 0 {
			body = "@echo off\r\n" + record + "echo " + name + " failed 1>&2\r\nexit /b " + strconv.Itoa(code) + "\r\n"
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
	}

	stubRoot := t.TempDir()
	if strings.Contains(stubRoot, " ") {
		t.Skipf("temp directory %q contains a space: the stub directory could not be reached unquoted", stubRoot)
	}

	runScript := func(t *testing.T, netshCode, routeCode int, serverIPV6, mtu string) (int, string, string) {
		t.Helper()

		dir, err := os.MkdirTemp(stubRoot, "stubs")
		require.NoError(t, err)
		logPath := filepath.Join(dir, "calls.log")
		stubTool(t, dir, "netsh.cmd", logPath, netshCode)
		stubTool(t, dir, "route.cmd", logPath, routeCode)

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

	// 防回归：Go 把空参数编码为字面 ""，cmd 会把这对引号留在 %7 里，脚本必须用 %~7 去引号，
	// 否则没有服务端 IPv6 时会误入 ipv6 分支。存根永远成功，只有调用日志能区分分支。
	t.Run("empty server ipv6 keeps the ipv6 branch off", func(t *testing.T) {
		code, out, calls := runScript(t, 0, 0, "", "1500")
		require.Equal(t, 0, code, "%s", out)
		require.Contains(t, calls, "set dns name=tun-easyss-test static 223.5.5.5",
			"the dns passed by the caller must be applied:\n%s", calls)
		require.NotContains(t, calls, "ipv6",
			"an empty server ipv6 (Go passes it as a literal \"\") must not install ipv6 routes:\n%s", calls)
	})

	t.Run("empty mtu keeps the adapter default", func(t *testing.T) {
		// 调用方没给 MTU 时不得凭空写一个值：适配器 MTU 与 netstack 不一致时只会静默丢包。
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
		code, out, _ := runScript(t, 9009, 0, "2001:db8::2", "1500")
		require.NotEqualf(t, 0, code, "an ipv6 command failure must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, failureMarker)

		code, out, _ = runScript(t, 0, 0, "2001:db8::2", "1500")
		require.Equal(t, 0, code, "the ipv6 branch must not fail when every command succeeds:\n%s", out)
	})
}

type closeScriptStub struct {
	// probeCode 是 netsh "show interface" 的退出码：0 = 接口还在，1 = 接口未注册
	// （正常关闭的形态），9009 = netsh 本身跑不起来。
	probeCode int
	tableRows []string
}

// 两条契约：发出创建脚本装过的同一路由阶梯与 ipv6 地址（netsh add address 是持久的，
// 创建脚本无法重复应用，只能由关闭脚本删除）；设备已不存在时不报失败，
// 路由真的残留时必须以非零码退出——残留的分流默认路由会把全机 IPv4 流量送进没人读的 TUN。
func TestCloseTunScriptCleanup(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "client", "tun", "scripts", scripts.CloseTunFilename))
	require.NoError(t, err)

	comspec := os.Getenv("COMSPEC")
	if comspec == "" {
		comspec = "cmd.exe"
	}

	stubRoot := t.TempDir()
	if strings.Contains(stubRoot, " ") {
		t.Skipf("temp directory %q contains a space: the stub directory could not be reached unquoted", stubRoot)
	}

	// 记录为空（脚本在探测阶段就退出）不是错误，由各子用例自行断言。
	runClose := func(t *testing.T, stub closeScriptStub, args ...string) (int, string, []string) {
		t.Helper()

		dir, err := os.MkdirTemp(stubRoot, "stubs")
		require.NoError(t, err)
		record := filepath.Join(dir, "record.txt")

		recordCall := "echo %* >> \"" + record + "\"\r\n"

		// netsh 打印的错误文本随系统语言变化、与真正失败无法区分，只能看退出码。
		netshBody := "@echo off\r\n" + recordCall +
			"if \"%1\"==\"interface\" if \"%2\"==\"show\" exit /b " + strconv.Itoa(stub.probeCode) + "\r\n" +
			"exit /b 0\r\n"
		require.NoError(t, os.WriteFile(filepath.Join(dir, "netsh.cmd"), []byte(netshBody), 0o644))

		// 网关列用 198.18.0.1，与脚本残留探测 "tokens=1,2,3" 的第 1、3 列一致。
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

	// 引擎先停、wintun 适配器注销、路由随之消失，这是正常关闭，不是失败。
	t.Run("a device that is already gone is not a failure", func(t *testing.T) {
		code, out, lines := runClose(t, closeScriptStub{probeCode: 1},
			"tun-easyss-test", "198.18.0.1", "2001:db8::1")

		require.Equal(t, 0, code,
			"an adapter that is already unregistered must not be reported as a cleanup failure:\n%s", out)
		require.NotContains(t, out, closeFailureMarker, "nothing was left to clean up")
		require.Len(t, lines, 1, "only the interface probe may run when the device is gone:\n%v", lines)
		require.Contains(t, lines[0], "show interface")
	})

	// 只认"接口未注册"（恰好返回 1）：netsh 自己跑不起来（9009）时仍要执行删除与残留探测。
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

	// 删除被真正拒绝时路由留在表里，就是"停止 TUN 后断网"的成因，必须以非零码退出。
	t.Run("residual routes fail the script", func(t *testing.T) {
		code, out, _ := runClose(t, closeScriptStub{tableRows: []string{
			"Network Destination        Netmask          Gateway       Interface  Metric",
			"          1.0.0.0        255.0.0.0      198.18.0.1      198.18.0.1      5",
		}}, "tun-easyss-test", "198.18.0.1")

		require.NotEqualf(t, 0, code, "a split route that survived the deletes must not exit 0:\n%s", out)
		require.Contains(t, out, closeFailureMarker)
	})

	// 适配器自带的默认路由（set address ... gateway 留下的持久路由）与别的 VPN 装的大段路由
	// 不在本脚本删过的那 8 条里，算成残留会让每次关闭都告警。
	t.Run("routes the script never installed are not residue", func(t *testing.T) {
		code, out, _ := runClose(t, closeScriptStub{tableRows: []string{
			"Network Destination        Netmask          Gateway       Interface  Metric",
			"          0.0.0.0          0.0.0.0       198.18.0.1       198.18.0.1      1",
			"       198.18.0.0      255.255.0.0         On-link        198.18.0.1    261",
		}}, "tun-easyss-test", "198.18.0.1")

		require.Equal(t, 0, code, "a route the close script never installs is not residue:\n%s", out)
		require.NotContains(t, out, closeFailureMarker)
	})

	// 空网关会让 route delete 丢掉网关参数（可能删掉物理链路上的同名路由），
	// 也会让残留探测匹配上每一行无法解析的表项。
	t.Run("a missing gateway is refused", func(t *testing.T) {
		code, out, _ := runClose(t, closeScriptStub{}, "tun-easyss-test")

		require.NotEqualf(t, 0, code, "a missing tun gateway must not be treated as success:\n%s", out)
		require.Contains(t, out, closeFailureMarker)
	})
}
