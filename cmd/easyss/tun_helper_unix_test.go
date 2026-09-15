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

	"github.com/stretchr/testify/require"
)

// fdTestSocketPath returns a short socket path in its own directory: the
// sun_path of a Unix socket is limited to about 104 bytes, and t.TempDir()
// embeds the test name, which is long enough to exceed that limit on macOS.
func fdTestSocketPath(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "easyss-fd")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	return filepath.Join(dir, "fd.sock")
}

// TestReceiveFdReportsAFailedHelperImmediately is the regression test for the
// blind wait on the fd socket: a helper that fails before it can send the fd
// (the create script exits non-zero, for instance) fails long before the
// parent's 30s accept deadline, and what the user saw was a timeout instead of
// that failure. The helper now announces the give-up by connecting to the
// socket without an fd (see notifyStartFailure), and the parent has to report
// it at once, with the reason, so the tray does not have to send the user to
// the log file.
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

// TestReceiveFdReportsAGiveUpWithoutReason covers the helper that could not name
// a reason: the connection alone still has to fail the start instead of letting
// the parent wait for an fd that will never come.
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

// TestFailurePayload keeps the failure text usable in a desktop notification:
// one line, even when it carries the newlines of a failed platform script, and
// never longer than the socket message the parent reads.
func TestFailurePayload(t *testing.T) {
	require.Nil(t, failurePayload(nil), "a helper without a reason sends nothing")

	payload := string(failurePayload(errors.New("run create script: \n  \"bash /tmp/x.sh\":\texit status 1\n")))
	require.Equal(t, `run create script: "bash /tmp/x.sh": exit status 1`, payload)

	// Over the cap both ends survive: the failing step at the front and the
	// script's own "failed near:" summary at the back.
	long := string(failurePayload(errors.New("start of the reason " +
		strings.Repeat("x", 4*maxHelperFailureReason) + " failed near: route")))
	require.Len(t, long, maxHelperFailureReason, "the parent reads exactly one message of this size")
	require.True(t, strings.HasPrefix(long, "start of the reason"), "the front has to survive: %q", long)
	require.True(t, strings.HasSuffix(long, "failed near: route"), "the summary at the back has to survive: %q", long)
	require.Contains(t, long, " ... ")
}

// TestHelperFailureReasonCarriesTheScriptDiagnostics pins what the tray
// notification shows: the real create script of the platform runs here with
// stub tools that reject every call, and the reason the helper hands to the
// parent has to carry the script's own diagnostics — what failed and its
// "failed near:" summary — not just "exit status 1".
//
// The stubs also keep the test from reconfiguring the machine it runs on: the
// linux script only reaches for "ip", the darwin one for "ifconfig" and
// "route".
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

	err := runCreateScript("tun-easyss-test", "198.18.0.1/16", "198.18.0.1", "192.168.3.1", "", "", "", "")
	require.Error(t, err, "every stubbed tool rejects its call: the script has to report that")

	reason := string(failurePayload(fmt.Errorf("run create script: %w", err)))
	require.Contains(t, reason, "stub tool rejects the call", "the reason has to carry what the script reported")
	require.Contains(t, reason, "failed near:", "the script's summary is the part the user acts on")
	require.Equal(t, 1, strings.Count(reason, "create script"),
		"only giveUp names the step: the error it wraps must not repeat it: %q", reason)
	require.NotContains(t, reason, "\n", "a notification cannot render the script's newlines")
	require.LessOrEqual(t, len(reason), maxHelperFailureReason)
}

// TestReceiveFdReceivesTheSentFd guards the same path from the other side: the
// give-up signal must not make the parent reject the fd a healthy helper sends.
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

	// The received descriptor has to be the read end of the pipe the "helper"
	// sent, not just some number.
	received := os.NewFile(uintptr(fd), "received-fd")
	t.Cleanup(func() { received.Close() }) //nolint:errcheck

	_, err = pipeWriter.Write([]byte("tun"))
	require.NoError(t, err)
	buf := make([]byte, 3)
	_, err = io.ReadFull(received, buf)
	require.NoError(t, err)
	require.Equal(t, "tun", string(buf))
}
