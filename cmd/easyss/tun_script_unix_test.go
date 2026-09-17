//go:build (linux || darwin) && !headless

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/scripts"
	"github.com/stretchr/testify/require"
)

// 这里检查 linux 和 darwin 的创建脚本是否遵守与
// create_tun_dev_windows.bat 实现的、且由 tun_script_windows_test.go 针对
// cmd.exe 固定下来的相同的退出码契约：只有脚本以 0 退出时调用方才保留
// TUN 路由，否则在 stderr 上报失败的步骤。
//
// linux 脚本曾经无条件以 0 退出——run_idem 把错误回显到 stderr，但它的
// "case" 总是返回 0，而且脚本的最后一条命令就是一次 run_idem 调用——所以
// 被拒绝的 "ip addr replace" 或路由会留下一个只配置了一半的隧道，而 helper
// 和托盘都以为 TUN 已启用。darwin 脚本则完全没有逐命令检查：没有服务器
// IPv6 地址时它以 "route add -net 128.0.0.0/1" 结尾，因此失败的 ifconfig 或
// 任何更早失败的路由都被最后一次成功的 route add 掩盖了。
//
// 两个脚本都会像 cmd/easyss/tun_helper_linux.go 和 tun_helper_darwin.go
// 那样被真实运行，stub 工具放在 PATH 最前面：否则这些工具会重新配置运行
// 测试的机器的网络（而且需要 root 权限）。stub 工具通过 shell 自身的 PATH
// 查找被找到，每次调用都会把参数追加到自己的 <工具名>.log 日志中（参见
// stubScript 和 toolInvocations），这正是证明一次失败没有跳过脚本其余
// 部分的依据。

// stubScript 返回 stub 工具写入的 shell 主体。每次调用都会在工具应答前把
// 它的参数追加到 <name>.log（name 为工具名），因此测试可以知道脚本调用
// 了它多少次、用什么参数调用：是否把这次调用当作失败由脚本自己决定，
// 这正是断言所要验证的。
func stubScript(dir, name, answer string) string {
	return "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + quoteForScript(filepath.Join(dir, name+".log")) + "\n" +
		answer
}

// quoteForScript 把路径转义为 POSIX shell 单引号字符串，因此包含空格或
// 引号的测试目录仍然能生成可运行的 stub。
func quoteForScript(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// stubTool 生成一个以 code 退出的工具，失败时把 marker 打印到 stderr。
func stubTool(t *testing.T, dir, name string, code int, marker string) {
	t.Helper()

	answer := "exit 0\n"
	if code != 0 {
		answer = "echo " + marker + " 1>&2\nexit " + strconv.Itoa(code) + "\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(stubScript(dir, name, answer)), 0o755))
}

// failTool 生成一个总是失败的工具，输出给定的内容（已为 shell 转义）并以
// code 退出。
func failTool(t *testing.T, dir, name, output string, code int) {
	t.Helper()

	answer := "echo " + output + " 1>&2\nexit " + strconv.Itoa(code) + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(stubScript(dir, name, answer)), 0o755))
}

// stubStep 是脚本化序列中的一个应答：当 fail 为 true 时工具的第 n 次调用
// 失败。超出序列的调用一律成功。
type stubStep struct {
	fail bool
}

// sequenceTool 生成一个按顺序走过各步骤的工具，因此测试可以让某一个步骤
// 失败而其余步骤全部成功。计数器保存在文件中，因为每次调用都是独立的
// 进程。
func sequenceTool(t *testing.T, dir, name, marker string, steps ...stubStep) {
	t.Helper()

	counter := quoteForScript(filepath.Join(dir, name+".n"))
	answer := "n=$(cat " + counter + " 2>/dev/null || echo 0)\n" +
		"n=$((n + 1))\n" +
		"echo $n > " + counter + "\n" +
		"case $n in\n"
	for i, step := range steps {
		body := ": ;;"
		if step.fail {
			body = "echo " + marker + " 1>&2; exit 1 ;;"
		}
		answer += "  " + strconv.Itoa(i+1) + ") " + body + "\n"
	}
	answer += "esac\nexit 0\n"

	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(stubScript(dir, name, answer)), 0o755))
}

// toolLog 返回 stub 工具记录的全部调用：每行一次调用的实参，
// 因此测试既能数调用次数，也能看到每次调用真正传了什么。
func toolLog(t *testing.T, dir, name string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, name+".log"))
	require.NoError(t, err, "the stub tool of %s never ran", name)
	return string(data)
}

// toolInvocations 返回指定 stub 工具运行了多少次。日志缺失时它会使测试
// 失败：否则空日志会被读成"脚本从未调用该工具"，掩盖计数断言失败的原因。
func toolInvocations(t *testing.T, dir, name string) int {
	t.Helper()

	return len(strings.Split(strings.TrimSpace(toolLog(t, dir, name)), "\n"))
}

// runScriptStubbed 通过 shell 运行给定的创建脚本，stub 目录位于 PATH 最前，
// 返回其退出码以及合并后的输出（脚本的诊断信息）。脚本作为参数传给
// shell，因此解释器无需解析 shebang，而脚本调用的 stub 会记录实际运行的
// 内容。
func runScriptStubbed(t *testing.T, shell, script, stubDir string, args ...string) (int, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "create_tun_dev_test.sh")
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))

	cmd := exec.Command(shell, append([]string{path}, args...)...)
	cmd.Env = append(os.Environ(), "PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()

	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr, "running the create script with stubbed tools: %v\n%s", err, out)
		code = exitErr.ExitCode()
	}
	return code, string(out)
}

// requireShell 在脚本所用的解释器未安装时跳过测试，因此极简环境不会因为
// 缺少 shell 而失败。
func requireShell(t *testing.T, shell string) {
	t.Helper()

	if _, err := exec.LookPath(shell); err != nil {
		t.Skipf("%s is unavailable in this environment: %v", shell, err)
	}
}

// linuxScriptArgs 与 client/tun/tun.go 传给 linux 脚本的参数保持一致：
// device、tun ip/prefix、tun gw、local gw、tun ipv6、tun gw ipv6、
// server ipv6、local gw ipv6。
func linuxScriptArgs(withV6 bool) []string {
	args := []string{"tun-easyss-test", "198.18.0.1/16", "198.18.0.1", "192.168.3.1"}
	if !withV6 {
		return args
	}
	return append(args, "2001:db8::1/64", "fe80::1", "2001:db8::2", "fe80::2")
}

// darwinScriptArgs 与 client/tun/tun.go 的 darwinScriptArgs 传给
// create_tun_dev_darwin.sh 的参数保持一致：第五个参数是裸的 IPv6 地址，
// 因为脚本自己把 "/64" 拼到 ifconfig 的 inet6 参数上，由调用方负责剥掉
// TunIPV6Sub 自带的前缀长度。
func darwinScriptArgs(withV6 bool) []string {
	args := []string{"utun8", "198.18.0.1", "198.18.0.1", "192.168.3.1"}
	if !withV6 {
		return args
	}
	return append(args, "2001:db8::1", "fe80::1", "2001:db8::2", "fe80::2")
}

// TestCreateTunScriptLinuxExitCode 固定 scripts/create_tun_dev.sh 的退出码
// 契约。
func TestCreateTunScriptLinuxExitCode(t *testing.T) {
	requireShell(t, "bash")

	const marker = "[create_tun_dev]"
	// 脚本每个步骤调用一次 "ip"：addr、link 和 8 个路由块，存在服务器 ipv6
	// 时还有 ipv6 地址和 2 条 ipv6 路由。
	const stepsV4 = 10
	const stepsV6 = 13

	t.Run("every command succeeds", func(t *testing.T) {
		dir := t.TempDir()
		stubTool(t, dir, "ip", 0, marker)

		code, out := runScriptStubbed(t, "bash", string(scripts.CreateTunDevSh), dir, linuxScriptArgs(false)...)
		require.Equal(t, 0, code, "the create script must exit 0 when every command succeeds:\n%s", out)
		require.NotContains(t, out, "failed near", "a successful run must not report a failing step")
		require.Equal(t, stepsV4, toolInvocations(t, dir, "ip"), "every step must have run")
	})

	t.Run("failing address fails the script", func(t *testing.T) {
		dir := t.TempDir()
		// 只有地址步骤失败而路由仍然成功：这是调用方必须回滚的部分配置
		// 设备，也是过去会被报告为成功的情况。
		sequenceTool(t, dir, "ip", marker, stubStep{fail: true})

		code, out := runScriptStubbed(t, "bash", string(scripts.CreateTunDevSh), dir, linuxScriptArgs(false)...)
		require.NotEqualf(t, 0, code, "a rejected ip addr replace must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, "failed near: addr",
			"the failing step must be reported on stderr so the tray notification can show it")
		require.Equal(t, stepsV4, toolInvocations(t, dir, "ip"),
			"one rejected block must not skip the remaining steps")
	})

	t.Run("failing route fails the script", func(t *testing.T) {
		dir := t.TempDir()
		// 地址和链路都配置成功，第二条路由（2.0.0.0/7）被拒绝。
		sequenceTool(t, dir, "ip", marker, stubStep{}, stubStep{}, stubStep{}, stubStep{fail: true})

		code, out := runScriptStubbed(t, "bash", string(scripts.CreateTunDevSh), dir, linuxScriptArgs(false)...)
		require.NotEqualf(t, 0, code, "a rejected route must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, "failed near: route")
		require.Equal(t, stepsV4, toolInvocations(t, dir, "ip"),
			"the ladder must be attempted to the end: one rejected block must not skip the rest")
	})

	t.Run("failing ipv6 route fails the script", func(t *testing.T) {
		dir := t.TempDir()
		// 只有最后一步（第二条 ipv6 路由）失败：它之前的全部内容都已安装，
		// 这正是回滚必须撤销的状态。
		steps := make([]stubStep, stepsV6)
		steps[stepsV6-1] = stubStep{fail: true}
		sequenceTool(t, dir, "ip", marker, steps...)

		code, out := runScriptStubbed(t, "bash", string(scripts.CreateTunDevSh), dir, linuxScriptArgs(true)...)
		require.NotEqualf(t, 0, code, "a rejected ipv6 route must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, "failed near: v6-route")
	})

	t.Run("already configured state stays successful", func(t *testing.T) {
		// keep-alive 在休眠/唤醒后会重新运行脚本：对于未干净结束的会话
		// 遗留下来的状态，iproute2 会应答 "File exists"。这不是失败，不能
		// 让 helper 退出或让托盘报错。
		dir := t.TempDir()
		failTool(t, dir, "ip", "'RTNETLINK answers: File exists'", 2)

		code, out := runScriptStubbed(t, "bash", string(scripts.CreateTunDevSh), dir, linuxScriptArgs(false)...)
		require.Equal(t, 0, code, "an already configured address is not a failure:\n%s", out)
		require.NotContains(t, out, "failed near")
	})
}

// TestCreateTunScriptDarwinExitCode 固定 scripts/create_tun_dev_darwin.sh 的
// 退出码契约，包括过去会被掩盖的情况：失败的 ifconfig 之后跟着成功的
// route add。
func TestCreateTunScriptDarwinExitCode(t *testing.T) {
	requireShell(t, "sh")

	const marker = "[create_tun_dev_darwin]"
	// 脚本对每个 IPv4 块（8 个块加 198.18.0.0/15）执行一次 route，存在服务器
	// ipv6 时再为 IPv6 默认路由多执行一次。
	const routesV4 = 9
	const routesV6 = 10

	// stubDarwin 生成子测试所需的 ifconfig 和 route stub，当 routeFail 返回
	// true 时第 n 次 route 调用失败。
	stubDarwin := func(t *testing.T, ifconfigFail bool, routeFail func(n int) bool) string {
		t.Helper()

		dir := t.TempDir()
		stubTool(t, dir, "ifconfig", boolCode(ifconfigFail), marker)

		steps := make([]stubStep, routesV6)
		for i := range steps {
			steps[i] = stubStep{fail: routeFail(i + 1)}
		}
		sequenceTool(t, dir, "route", marker, steps...)
		return dir
	}

	t.Run("every command succeeds", func(t *testing.T) {
		dir := stubDarwin(t, false, func(int) bool { return false })

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(false)...)
		require.Equal(t, 0, code, "the create script must exit 0 when every command succeeds:\n%s", out)
		require.NotContains(t, out, "failed near")
		require.Equal(t, 1, toolInvocations(t, dir, "ifconfig"))
		require.Equal(t, routesV4, toolInvocations(t, dir, "route"))
	})

	t.Run("failing ifconfig fails the script even when the routes succeed", func(t *testing.T) {
		// 这就是回归所在：没有服务器 IPv6 地址时，脚本过去以
		// "route add -net 128.0.0.0/1" 结尾并退出 0，于是设备没有地址，
		// 而调用方却以为 TUN 已启用。
		dir := stubDarwin(t, true, func(int) bool { return false })

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(false)...)
		require.NotEqualf(t, 0, code, "a failed ifconfig must not be masked by the route adds:\n%s", out)
		require.Contains(t, out, "failed near: ifconfig-ipv4")
		require.Equal(t, routesV4, toolInvocations(t, dir, "route"),
			"the script reports the whole run: it does not stop at the first failure")
	})

	t.Run("failing ifconfig in the ipv6 branch fails the script", func(t *testing.T) {
		// ipv6 分支有自己的 ifconfig 调用，过去也没有任何退出码覆盖它。
		dir := t.TempDir()
		sequenceTool(t, dir, "ifconfig", marker, stubStep{}, stubStep{fail: true})
		stubTool(t, dir, "route", 0, marker)

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(true)...)
		require.NotEqualf(t, 0, code, "a failed ipv6 ifconfig must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, "failed near: ifconfig-ipv6")
		require.Equal(t, routesV6, toolInvocations(t, dir, "route"))
	})

	t.Run("failing ipv4 route fails the script", func(t *testing.T) {
		dir := stubDarwin(t, false, func(n int) bool { return n == 3 })

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(false)...)
		require.NotEqualf(t, 0, code, "a rejected route add must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, "failed near: route-4.0.0.0/6")
		require.Equal(t, routesV4, toolInvocations(t, dir, "route"))
	})

	t.Run("failing ipv6 route fails the script", func(t *testing.T) {
		dir := stubDarwin(t, false, func(n int) bool { return n == routesV6 })

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(true)...)
		require.NotEqualf(t, 0, code, "a rejected ipv6 route must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, "failed near: route-v6-default")
	})

	t.Run("the ipv6 address reaches ifconfig with a single prefix", func(t *testing.T) {
		// 这个断言正是此前缺失的一环：stub 化的 ifconfig 从不检查实参，于是
		// "2001:0db8:0:f101::1/64/64" 一路走到用户的 macOS 上被 ifconfig 以
		// "bad value" 拒绝，创建脚本整体失败、TUN 起不来。脚本自己拼 "/64"，
		// 因此调用方必须剥掉 TunIPV6Sub 自带的前缀（client/tun/tun.go 的
		// darwinScriptArgs 与 tun_helper_darwin.go 的 runCreateScript）。
		dir := stubDarwin(t, false, func(int) bool { return false })

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(true)...)
		require.Equal(t, 0, code, "%s", out)

		log := toolLog(t, dir, "ifconfig")
		require.Contains(t, log, "utun8 inet6 2001:db8::1/64 up",
			"the script appends the prefix length to the bare address it is given")
		require.NotContains(t, log, "/64/64", "a doubled prefix length is what ifconfig rejects")
	})

	t.Run("the ipv6 branch stays a no-op without a server ipv6", func(t *testing.T) {
		dir := stubDarwin(t, false, func(int) bool { return false })

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(false)...)
		require.Equal(t, 0, code, "the ipv6 branch must not run without a server ipv6 address:\n%s", out)
		require.Equal(t, 1, toolInvocations(t, dir, "ifconfig"), "only the ipv4 ifconfig may run")
	})

	t.Run("already configured routes stay successful", func(t *testing.T) {
		// macOS 的 "route add" 拒绝重复添加路由并报告 "File exists"：
		// keep-alive 在休眠/唤醒后的重跑绝不能把这种情况变成失败，否则
		// helper 会退出，托盘每 10 秒都会报告一次虚假的 "recreating TUN
		// routes"。
		dir := t.TempDir()
		stubTool(t, dir, "ifconfig", 0, marker)
		failTool(t, dir, "route", "'route: writing to routing socket: File exists'", 1)

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(false)...)
		require.Equal(t, 0, code, "an already configured route is not a failure:\n%s", out)
		require.NotContains(t, out, "failed near")
	})
}

// TestCreateScriptsGuardEveryCommand 是上述测试背后的一个轻量结构守卫：
// 那些测试证明脚本会报告被测到的失败，而这个测试捕获新增的、没有守卫的
// "ip"/"ifconfig"/"route" 命令——这正是本文件要防的那类 bug。只检查脚本
// 用自身工具发出的命令；helper 的函数定义和注释会被跳过。
func TestCreateScriptsGuardEveryCommand(t *testing.T) {
	for _, tc := range []struct {
		name     string
		script   string
		wrappers []string
		tools    []string
	}{
		{
			name:     "linux",
			script:   string(scripts.CreateTunDevSh),
			wrappers: []string{"run_idem "},
			tools:    []string{"ip "},
		},
		{
			name:     "darwin",
			script:   string(scripts.CreateTunDevDarwinSh),
			wrappers: []string{"fail "},
			tools:    []string{"ifconfig ", "route "},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Shell 注释会跨越多行，其续行以普通单词开头：如果不跟踪注释
			// 块，像 "allowed to fail calls fail, which records its step name"
			// 这样的行就会被误报为工具调用。
			inComment := false
			for line := range strings.SplitSeq(tc.script, "\n") {
				line = strings.TrimSpace(line)
				if inComment {
					if strings.HasPrefix(line, "#") {
						continue
					}
					// 注释块到此结束：这一行是代码，必须落入下面的检查
					// 而不是被跳过，否则紧跟在注释下的命令会被漏看。
					inComment = false
				}
				switch {
				case line == "":
					continue
				case strings.HasPrefix(line, "#"):
					inComment = true
					continue
				}
				if !slices.ContainsFunc(tc.tools, func(tool string) bool {
					return strings.HasPrefix(line, tool) ||
						strings.HasPrefix(line, tc.wrappers[0]) // helper 自身的定义
				}) {
					continue
				}
				if strings.Contains(line, "()") || strings.HasPrefix(line, "}") {
					continue // 函数定义或其右花括号
				}
				if !slices.ContainsFunc(tc.wrappers, func(w string) bool {
					return strings.HasPrefix(line, w)
				}) {
					t.Errorf("%s: %q calls a tool without an exit code guard, its failure would be invisible",
						tc.name, line)
				}
			}
		})
	}
}

// boolCode 把布尔值映射为退出码，这样 stub 表格读起来是"该工具失败"而不是
// 一个魔法数字。
func boolCode(fail bool) int {
	if fail {
		return 1
	}
	return 0
}
