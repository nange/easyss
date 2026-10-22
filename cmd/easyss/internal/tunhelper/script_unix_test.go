//go:build (linux || darwin) && !headless

package tunhelper

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/scripts"
	"github.com/stretchr/testify/require"
)

// 两个创建脚本共用同一份退出码契约：只有以 0 退出时调用方才保留 TUN 路由，
// 否则在 stderr 上报失败的步骤。脚本以真实 shell 运行，stub 工具放在 PATH 最前，
// 否则会重新配置运行测试的机器的网络。

// stubScript 的每次调用都先把实参追加到 <name>.log，测试据此知道调用次数与参数。
func stubScript(dir, name, answer string) string {
	return "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + quoteForScript(filepath.Join(dir, name+".log")) + "\n" +
		answer
}

func quoteForScript(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func stubTool(t *testing.T, dir, name string, code int, marker string) {
	t.Helper()

	answer := "exit 0\n"
	if code != 0 {
		answer = "echo " + marker + " 1>&2\nexit " + strconv.Itoa(code) + "\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(stubScript(dir, name, answer)), 0o755))
}

func failTool(t *testing.T, dir, name, output string, code int) {
	t.Helper()

	answer := "echo " + output + " 1>&2\nexit " + strconv.Itoa(code) + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(stubScript(dir, name, answer)), 0o755))
}

// 第 n 次调用失败（fail 为 true 时），超出序列的调用一律成功。
type stubStep struct {
	fail bool
}

// 计数器保存在文件里：每次调用都是独立进程。
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

func toolLog(t *testing.T, dir, name string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, name+".log"))
	require.NoError(t, err, "the stub tool of %s never ran", name)
	return string(data)
}

// 日志缺失时使测试失败：空日志会被读成"脚本从未调用该工具"，掩盖计数断言失败的原因。
func toolInvocations(t *testing.T, dir, name string) int {
	t.Helper()

	return len(strings.Split(strings.TrimSpace(toolLog(t, dir, name)), "\n"))
}

// stub 目录位于 PATH 最前；脚本作为参数传给 shell，解释器无需解析 shebang。
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

func requireShell(t *testing.T, shell string) {
	t.Helper()

	if _, err := exec.LookPath(shell); err != nil {
		t.Skipf("%s is unavailable in this environment: %v", shell, err)
	}
}

// 实参来自 client/tun.ScriptArgs，与生产代码共用同一个构造器：手抄字面量的位次
// 一挪，只有真正跑起脚本才会暴露。
func linuxScriptArgs(withV6 bool) []string {
	args := scriptArgsFixture(withV6)
	args.Dev.TunIPV6Sub = "2001:db8::1/64"
	args.Dev.Device = "tun-easyss-test"
	return args.CreateFor(tun.PlatformLinux)
}

func darwinScriptArgs(withV6 bool) []string {
	args := scriptArgsFixture(withV6)
	args.Dev.TunIPV6Sub = "2001:db8::1/64"
	args.Dev.Device = "utun8"
	return args.CreateFor(tun.PlatformDarwin)
}

func TestCreateTunScriptLinuxExitCode(t *testing.T) {
	requireShell(t, "bash")

	const marker = "[create_tun_dev]"
	const stepsV4 = 11
	const stepsV6 = 14

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
		// 地址步骤失败而路由仍然成功：调用方必须回滚这个半配置的设备。
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
		sequenceTool(t, dir, "ip", marker, stubStep{}, stubStep{}, stubStep{}, stubStep{fail: true})

		code, out := runScriptStubbed(t, "bash", string(scripts.CreateTunDevSh), dir, linuxScriptArgs(false)...)
		require.NotEqualf(t, 0, code, "a rejected route must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, "failed near: route")
		require.Equal(t, stepsV4, toolInvocations(t, dir, "ip"),
			"the ladder must be attempted to the end: one rejected block must not skip the rest")
	})

	t.Run("failing ipv6 route fails the script", func(t *testing.T) {
		dir := t.TempDir()
		steps := make([]stubStep, stepsV6)
		steps[stepsV6-1] = stubStep{fail: true}
		sequenceTool(t, dir, "ip", marker, steps...)

		code, out := runScriptStubbed(t, "bash", string(scripts.CreateTunDevSh), dir, linuxScriptArgs(true)...)
		require.NotEqualf(t, 0, code, "a rejected ipv6 route must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, "failed near: v6-route")
	})

	t.Run("a missing MTU argument is not fatal", func(t *testing.T) {
		// 第 9 个实参可选：只给 8 个时脚本仍要配置地址与路由，只跳过 MTU。
		// 写成 $9 会让 darwin 脚本的 set -u 以 "unbound variable" 中止。
		dir := t.TempDir()
		stubTool(t, dir, "ip", 0, marker)

		code, out := runScriptStubbed(t, "bash", string(scripts.CreateTunDevSh), dir, linuxScriptArgs(false)[:8]...)
		require.Equal(t, 0, code, "an absent MTU argument must not fail the create script:\n%s", out)
		require.Equal(t, stepsV4-1, toolInvocations(t, dir, "ip"),
			"only the mtu step may be skipped without the argument")
	})

	t.Run("already configured state stays successful", func(t *testing.T) {
		// keep-alive 重跑脚本时 iproute2 会应答 "File exists"，这不是失败。
		dir := t.TempDir()
		failTool(t, dir, "ip", "'RTNETLINK answers: File exists'", 2)

		code, out := runScriptStubbed(t, "bash", string(scripts.CreateTunDevSh), dir, linuxScriptArgs(false)...)
		require.Equal(t, 0, code, "an already configured address is not a failure:\n%s", out)
		require.NotContains(t, out, "failed near")
	})
}

func TestCreateTunScriptDarwinExitCode(t *testing.T) {
	requireShell(t, "sh")

	const marker = "[create_tun_dev_darwin]"
	const routesV4 = 9
	const routesV6 = 10

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
		require.Equal(t, 2, toolInvocations(t, dir, "ifconfig"),
			"the ipv4 address and the mtu are applied with ifconfig")
		require.Equal(t, routesV4, toolInvocations(t, dir, "route"))
	})

	t.Run("failing ifconfig fails the script even when the routes succeed", func(t *testing.T) {
		// 没有服务器 IPv6 地址时脚本以 "route add -net 128.0.0.0/1" 结尾并退出 0，
		// 设备没有地址而调用方以为 TUN 已启用。
		dir := stubDarwin(t, true, func(int) bool { return false })

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(false)...)
		require.NotEqualf(t, 0, code, "a failed ifconfig must not be masked by the route adds:\n%s", out)
		require.Contains(t, out, "failed near: ifconfig-ipv4")
		require.Equal(t, routesV4, toolInvocations(t, dir, "route"),
			"the script reports the whole run: it does not stop at the first failure")
	})

	t.Run("failing ifconfig in the ipv6 branch fails the script", func(t *testing.T) {
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
		// 脚本自己拼 "/64"，调用方必须剥掉 TunIPV6Sub 自带的前缀；
		// 否则 ifconfig 会以 "bad value" 拒绝 "2001:db8::1/64/64"，整个脚本失败。
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
		require.Equal(t, 2, toolInvocations(t, dir, "ifconfig"),
			"only the ipv4 address and the mtu may be applied, never the ipv6 address")
	})

	t.Run("a missing MTU argument is not fatal", func(t *testing.T) {
		// 带 set -u：第 9 个实参写成 $9 时，只给 8 个实参的调用会以 "unbound variable" 中止。
		dir := stubDarwin(t, false, func(int) bool { return false })

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(false)[:8]...)
		require.Equal(t, 0, code, "an absent MTU argument must not fail the create script:\n%s", out)
		require.NotContains(t, out, "unbound variable")
		require.Equal(t, 1, toolInvocations(t, dir, "ifconfig"),
			"only the ipv4 address may be applied without the argument")
		require.Equal(t, routesV4, toolInvocations(t, dir, "route"))
	})

	t.Run("already configured routes stay successful", func(t *testing.T) {
		// macOS 的 route add 拒绝重复添加并报告 "File exists"，重跑不能因此失败，
		// 否则托盘每 10 秒都会报一次虚假的 "recreating TUN routes"。
		dir := t.TempDir()
		stubTool(t, dir, "ifconfig", 0, marker)
		failTool(t, dir, "route", "'route: writing to routing socket: File exists'", 1)

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(false)...)
		require.Equal(t, 0, code, "an already configured route is not a failure:\n%s", out)
		require.NotContains(t, out, "failed near")
	})
}

// 结构守卫：捕获新增的、没有退出码守卫的 ip/ifconfig/route 命令。
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
			// Shell 注释的续行以普通单词开头：不跟踪注释块会把注释文本误报成工具调用。
			inComment := false
			for line := range strings.SplitSeq(tc.script, "\n") {
				line = strings.TrimSpace(line)
				if inComment {
					if strings.HasPrefix(line, "#") {
						continue
					}
					// 注释块到此结束：这一行是代码，必须落入下面的检查。
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

func boolCode(fail bool) int {
	if fail {
		return 1
	}
	return 0
}
