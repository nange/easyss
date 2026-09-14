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

// failureMarker is what create_tun_dev_windows.bat prints on stderr (and
// therefore what the user notification shows) when a command of the TUN
// configuration script failed.
const failureMarker = "[create_tun_dev_windows] failed near:"

// TestCreateTunScriptExitCode is the regression test for the TUN traffic loop
// a silently successful create script produced on Windows.
//
// cmd.exe returns 0 for a batch file without an explicit "exit /b" even when
// the commands inside it failed, so a script whose netsh/route commands were
// rejected still reported success: the client kept the TUN routes installed,
// marked tun2socks as started and notified nothing, while every packet went
// into a device that had no address and no DNS. The script now records the
// first failing step and exits non-zero, which is what this test pins down.
//
// The real script is run through cmd.exe exactly like client/tun/tun.go does,
// with a directory of stub tools prepended to PATH so that the failures are
// reproducible: netsh refuses to configure an adapter that does not exist and
// installing routes for real would need administrator rights. The stubs are
// ordinary batch files, which works because the script calls every tool with
// "call" (see the comment on the exit code contract in the script).
func TestCreateTunScriptExitCode(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", scripts.CreateTunFilename))
	require.NoError(t, err)

	comspec := os.Getenv("COMSPEC")
	if comspec == "" {
		comspec = "cmd.exe"
	}

	// stubTool writes a tool that exits with the given code, printing a marker
	// on stderr when it fails.
	stubTool := func(t *testing.T, dir, name string, code int) string {
		t.Helper()

		path := filepath.Join(dir, name)
		body := "@echo off\r\nexit /b " + strconv.Itoa(code) + "\r\n"
		if code != 0 {
			body = "@echo off\r\necho " + name + " failed 1>&2\r\nexit /b " + strconv.Itoa(code) + "\r\n"
		}
		require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
		return path
	}

	// A stub directory inside a path with spaces would be passed to the
	// unquoted tool invocations as several arguments, turning this test into a
	// quotation test instead of an exit code test.
	stubRoot := t.TempDir()
	if strings.Contains(stubRoot, " ") {
		t.Skipf("temp directory %q contains a space: the stub directory could not be reached unquoted", stubRoot)
	}

	// runScript runs the create script with netsh and route stubbed, and
	// returns its exit code together with the combined output. serverIPV6
	// switches the script into its ipv6 branch.
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

	// A stub directory inside a path with spaces would be passed to the
	// unquoted tool invocations as several arguments, turning this test into a
	// quotation test instead of an exit code test.
	if strings.ContainsAny(t.TempDir(), " ") {
		t.Skipf("TEMP %q contains a space: the stub directory could not be reached unquoted", os.Getenv("TEMP"))
	}

	t.Run("every command succeeds", func(t *testing.T) {
		code, out := runScript(t, 0, 0, "")
		require.Equal(t, 0, code, "the create script must exit 0 when every command succeeds:\n%s", out)
	})

	t.Run("failing netsh fails the script", func(t *testing.T) {
		// The address and DNS commands fail while the routes are installed:
		// this is the case that used to look like a successful start.
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
		// Only the ipv6 block can fail here, which means the ipv4 address and
		// routes were installed first: exactly the partly configured device
		// Manager.Start has to roll back.
		code, out := runScript(t, 9009, 0, "2001:db8::2")
		require.NotEqualf(t, 0, code, "an ipv6 command failure must not leave a zero exit code:\n%s", out)
		require.Contains(t, out, failureMarker)

		code, out = runScript(t, 0, 0, "2001:db8::2")
		require.Equal(t, 0, code, "the ipv6 branch must not fail when every command succeeds:\n%s", out)
	})
}
