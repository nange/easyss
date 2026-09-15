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

// The create scripts of linux and darwin are checked here for the same exit
// code contract create_tun_dev_windows.bat implements and
// tun_script_windows_test.go pins down for cmd.exe: the caller keeps the TUN
// routes installed only when the script exits 0, and reports the failing step
// on stderr otherwise.
//
// The linux script used to exit 0 unconditionally — run_idem echoed the error
// to stderr but its "case" always returned 0, and the last command of the
// script was a run_idem call — so a rejected "ip addr replace" or route left a
// half configured tunnel while the helper and the tray both believed TUN was
// up. The darwin script had no per-command check at all: without a server IPv6
// address it ended with "route add -net 128.0.0.0/1", so a failed ifconfig or
// any failed earlier route was masked by the success of the last route add.
//
// Both scripts are run for real, the way cmd/easyss/tun_helper_linux.go and
// tun_helper_darwin.go do, with stub tools first on PATH: the tools would
// otherwise reconfigure the network of the machine running the test (and need
// root to do it). The stubs are found through the shell's own PATH lookup, and
// the "-x" runScriptStubbed writes into the shebang records every command the
// script issued, which is what proves a failure did not skip the rest of the
// script.

// stubScript returns the shell body a stub tool is written with. Every
// invocation appends its arguments to invocations.log before the tool answers,
// so a test can tell how often the script called it and with what: the script
// itself decides whether that call was a failure, which is exactly what the
// assertions are about.
func stubScript(dir, name, answer string) string {
	return "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + quoteForScript(filepath.Join(dir, name+".log")) + "\n" +
		answer
}

// quoteForScript quotes a path for a POSIX shell single-quoted string, so a
// test directory containing spaces or quotes still yields a runnable stub.
func quoteForScript(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// stubTool writes a tool that exits with code, printing marker on stderr when
// it fails.
func stubTool(t *testing.T, dir, name string, code int, marker string) {
	t.Helper()

	answer := "exit 0\n"
	if code != 0 {
		answer = "echo " + marker + " 1>&2\nexit " + strconv.Itoa(code) + "\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(stubScript(dir, name, answer)), 0o755))
}

// failTool writes a tool that always fails with the given output (already
// quoted for the shell) and exit code.
func failTool(t *testing.T, dir, name, output string, code int) {
	t.Helper()

	answer := "echo " + output + " 1>&2\nexit " + strconv.Itoa(code) + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(stubScript(dir, name, answer)), 0o755))
}

// stubStep is one answer of a scripted sequence: the nth invocation of the
// tool fails when fail is true. Invocations beyond the sequence succeed.
type stubStep struct {
	fail bool
}

// sequenceTool writes a tool that walks steps in order, so a test can make one
// specific step fail while every other one succeeds. The counter lives in a
// file because each invocation is a separate process.
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

// toolInvocations returns how many times the named stub tool ran. It fails the
// test when the log is missing: an empty log would otherwise read as "the
// script never called the tool", hiding the reason a count assertion failed.
func toolInvocations(t *testing.T, dir, name string) int {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, name+".log"))
	require.NoError(t, err, "the stub tool of %s never ran", name)
	return len(strings.Split(strings.TrimSpace(string(data)), "\n"))
}

// runScriptStubbed runs the given create script through shell with the stub
// directory first on PATH, and returns its exit code together with the
// combined output (the script's diagnostics). The script is passed to the shell
// as an argument, so the interpreter does not have to resolve a shebang, and
// the stubs it calls are the ones recording what ran.
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

// requireShell skips the test when the interpreter the script is run with is
// not installed, so a minimal environment does not fail on a missing shell.
func requireShell(t *testing.T, shell string) {
	t.Helper()

	if _, err := exec.LookPath(shell); err != nil {
		t.Skipf("%s is unavailable in this environment: %v", shell, err)
	}
}

// linuxScriptArgs mirrors what client/tun/tun.go passes to the linux script:
// device, tun ip/prefix, tun gw, local gw, tun ipv6, tun gw ipv6,
// server ipv6, local gw ipv6.
func linuxScriptArgs(withV6 bool) []string {
	args := []string{"tun-easyss-test", "198.18.0.1/16", "198.18.0.1", "192.168.3.1"}
	if !withV6 {
		return args
	}
	return append(args, "2001:db8::1/64", "fe80::1", "2001:db8::2", "fe80::2")
}

// darwinScriptArgs mirrors what client/tun/tun.go passes to the darwin script.
func darwinScriptArgs(withV6 bool) []string {
	args := []string{"utun8", "198.18.0.1", "198.18.0.1", "192.168.3.1"}
	if !withV6 {
		return args
	}
	return append(args, "2001:db8::1/64", "fe80::1", "2001:db8::2", "fe80::2")
}

// TestCreateTunScriptLinuxExitCode pins the exit code contract of
// scripts/create_tun_dev.sh.
func TestCreateTunScriptLinuxExitCode(t *testing.T) {
	requireShell(t, "bash")

	const marker = "[create_tun_dev]"
	// The script issues one "ip" per step: addr, link and the 8 route blocks,
	// plus the ipv6 address and the 2 ipv6 routes when a server ipv6 exists.
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
		// Only the address step fails and the routes still succeed: this is
		// the partly configured device the caller has to roll back, and the
		// case that used to report success.
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
		// The address and the link come up, the first route is rejected.
		sequenceTool(t, dir, "ip", marker, stubStep{}, stubStep{}, stubStep{}, stubStep{fail: true})

		code, out := runScriptStubbed(t, "bash", string(scripts.CreateTunDevSh), dir, linuxScriptArgs(false)...)
		require.NotEqualf(t, 0, code, "a rejected route must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, "failed near: route")
		require.Equal(t, stepsV4, toolInvocations(t, dir, "ip"),
			"the ladder must be attempted to the end: one rejected block must not skip the rest")
	})

	t.Run("failing ipv6 route fails the script", func(t *testing.T) {
		dir := t.TempDir()
		// Only the last step (the second ipv6 route) fails: everything before
		// it was installed, which is exactly the state a rollback has to undo.
		steps := make([]stubStep, stepsV6)
		steps[stepsV6-1] = stubStep{fail: true}
		sequenceTool(t, dir, "ip", marker, steps...)

		code, out := runScriptStubbed(t, "bash", string(scripts.CreateTunDevSh), dir, linuxScriptArgs(true)...)
		require.NotEqualf(t, 0, code, "a rejected ipv6 route must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, "failed near: v6-route")
	})

	t.Run("already configured state stays successful", func(t *testing.T) {
		// The keep-alive re-runs the script after sleep/wake: iproute2 answers
		// "File exists" for state that survived a session which was not closed
		// cleanly. That is not a failure and must not make the helper exit or
		// the tray complain.
		dir := t.TempDir()
		failTool(t, dir, "ip", "'RTNETLINK answers: File exists'", 2)

		code, out := runScriptStubbed(t, "bash", string(scripts.CreateTunDevSh), dir, linuxScriptArgs(false)...)
		require.Equal(t, 0, code, "an already configured address is not a failure:\n%s", out)
		require.NotContains(t, out, "failed near")
	})
}

// TestCreateTunScriptDarwinExitCode pins the exit code contract of
// scripts/create_tun_dev_darwin.sh, including the case that used to be masked:
// a failing ifconfig followed by successful route adds.
func TestCreateTunScriptDarwinExitCode(t *testing.T) {
	requireShell(t, "sh")

	const marker = "[create_tun_dev_darwin]"
	// The script issues one route per IPv4 block (8 blocks plus 198.18.0.0/15)
	// and one more for the IPv6 default route when a server ipv6 exists.
	const routesV4 = 9
	const routesV6 = 10

	// stubDarwin writes the ifconfig and route stubs a subtest needs, with the
	// nth route call failing when routeFail says so.
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
		// This is the regression: without a server IPv6 address the script
		// used to end with "route add -net 128.0.0.0/1" and exit 0, so the
		// device had no address while the caller believed TUN was up.
		dir := stubDarwin(t, true, func(int) bool { return false })

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(false)...)
		require.NotEqualf(t, 0, code, "a failed ifconfig must not be masked by the route adds:\n%s", out)
		require.Contains(t, out, "failed near: ifconfig-ipv4")
		require.Equal(t, routesV4, toolInvocations(t, dir, "route"),
			"the script reports the whole run: it does not stop at the first failure")
	})

	t.Run("failing ifconfig in the ipv6 branch fails the script", func(t *testing.T) {
		// The ipv6 branch has its own ifconfig call, which no exit code used to
		// cover either.
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

	t.Run("the ipv6 branch stays a no-op without a server ipv6", func(t *testing.T) {
		dir := stubDarwin(t, false, func(int) bool { return false })

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(false)...)
		require.Equal(t, 0, code, "the ipv6 branch must not run without a server ipv6 address:\n%s", out)
		require.Equal(t, 1, toolInvocations(t, dir, "ifconfig"), "only the ipv4 ifconfig may run")
	})

	t.Run("already configured routes stay successful", func(t *testing.T) {
		// macOS "route add" refuses to duplicate a route and reports
		// "File exists": the keep-alive re-run after sleep/wake must not turn
		// that into a failure, which would make the helper exit and the tray
		// report a bogus "recreating TUN routes" every 10s.
		dir := t.TempDir()
		stubTool(t, dir, "ifconfig", 0, marker)
		failTool(t, dir, "route", "'route: writing to routing socket: File exists'", 1)

		code, out := runScriptStubbed(t, "sh", string(scripts.CreateTunDevDarwinSh), dir, darwinScriptArgs(false)...)
		require.Equal(t, 0, code, "an already configured route is not a failure:\n%s", out)
		require.NotContains(t, out, "failed near")
	})
}

// TestCreateScriptsGuardEveryCommand is a light structural guard behind the
// tests above: they prove the scripts report the failures that are exercised,
// this one catches a new "ip"/"ifconfig"/"route" command added without a guard,
// which is the bug class this file exists for. Only the commands the scripts
// issue with their own tools are checked; the helpers' definitions and comments
// are skipped.
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
			// Shell comments span several lines, and their continuation lines
			// start with an ordinary word: without following the block, a line
			// such as "allowed to fail calls fail, which records its step name"
			// would be reported as a tool invocation.
			inComment := false
			for line := range strings.SplitSeq(tc.script, "\n") {
				line = strings.TrimSpace(line)
				if inComment {
					if strings.HasPrefix(line, "#") {
						continue
					}
					// The comment block ends here: this line is code and has to
					// fall through to the checks below instead of being skipped,
					// which would leave the command right under a comment unseen.
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
						strings.HasPrefix(line, tc.wrappers[0]) // the helpers' own definitions
				}) {
					continue
				}
				if strings.Contains(line, "()") || strings.HasPrefix(line, "}") {
					continue // a function definition or its closing brace
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

// boolCode maps a boolean to an exit code, so a stub table reads as "this tool
// fails" instead of a magic number.
func boolCode(fail bool) int {
	if fail {
		return 1
	}
	return 0
}
