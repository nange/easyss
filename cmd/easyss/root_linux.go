//go:build linux

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"
)

// SpawnTunHelper launches a long-running elevated TUN helper process via
// pkexec. It creates a FIFO for lifecycle signalling (close the writer to
// trigger helper exit) and a Unix socket for receiving the TUN file
// descriptor. See spawnTunHelper for the full lifecycle.
//
// Returns:
//   - fifoWriter: close to signal the helper to shut down
//   - fdListener: accept a connection and call ReceiveFd to get the TUN fd
func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	// Linux uses an abstract socket (@-prefixed): it has no filesystem entry
	// (no stale-file removal, no chmod) and is immune to pkexec mount
	// namespace isolation.
	return spawnTunHelper(tunHelperElevator{
		label: "pkexec",
		command: func(innerCmd string) *exec.Cmd {
			// Pass HOME so the helper can find the config file; pkexec
			// sanitizes env.
			cmdArgs := []string{"env"}
			if home := os.Getenv("HOME"); home != "" {
				cmdArgs = append(cmdArgs, fmt.Sprintf("HOME=%s", home))
			}
			cmdArgs = append(cmdArgs, "sh", "-c", innerCmd)
			return exec.Command("pkexec", cmdArgs...)
		},
		innerCmd: func(exe, helperArgs, fifoPath string) string {
			return fmt.Sprintf("nohup '%s' %s < '%s' >/dev/null 2>&1 &", exe, helperArgs, fifoPath)
		},
	}, httpPort, fdSocketPath, logFile, logLevel, timeout)
}
