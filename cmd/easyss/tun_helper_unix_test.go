//go:build darwin || linux

package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
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
// it at once.
func TestReceiveFdReportsAFailedHelperImmediately(t *testing.T) {
	socketPath := fdTestSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint:errcheck

	notified := make(chan struct{})
	go func() {
		defer close(notified)
		notifyStartFailure(socketPath)
	}()

	start := time.Now()
	_, err = ReceiveFd(listener)
	elapsed := time.Since(start)
	<-notified

	require.Error(t, err, "a connection that carries no fd is a failed helper, not a started one")
	require.Less(t, elapsed, 5*time.Second,
		"the parent waited out its accept deadline instead of failing as soon as the helper gave up")
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
