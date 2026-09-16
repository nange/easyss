//go:build darwin

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SpawnTunHelper launches a long-running elevated TUN helper process via
// osascript with administrator privileges. It creates a FIFO for lifecycle
// signalling (close the writer to trigger helper exit) and a Unix socket for
// receiving the TUN file descriptor. See spawnTunHelper for the full
// lifecycle.
//
// Returns:
//   - fifoWriter: close to signal the helper to shut down
//   - fdListener: accept a connection and call ReceiveFd to get the TUN fd
func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	// macOS has no abstract Unix sockets: the fd socket is a filesystem entry
	// that must be cleaned of stale files before listen and made accessible
	// to the elevated (root) helper afterwards.
	return spawnTunHelper(tunHelperElevator{
		label: "osascript",
		command: func(innerCmd string) *exec.Cmd {
			scriptCmd := strings.ReplaceAll(innerCmd, "\"", "\\\"")
			script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", scriptCmd)
			return exec.Command("osascript", "-e", script)
		},
		innerCmd: func(exe, helperArgs, fifoPath string) string {
			return fmt.Sprintf("'%s' %s < '%s' &>/dev/null &", exe, helperArgs, fifoPath)
		},
		beforeListen: func(fdSocketPath string) {
			os.Remove(fdSocketPath) //nolint:errcheck
		},
		afterListen: func(fdSocketPath string) {
			// Ensure the socket is accessible by the elevated helper (root).
			os.Chmod(fdSocketPath, 0666) //nolint:errcheck
		},
		cleanupSocket: func(fdSocketPath string) {
			os.Remove(fdSocketPath) //nolint:errcheck
		},
	}, httpPort, fdSocketPath, logFile, logLevel, timeout)
}
