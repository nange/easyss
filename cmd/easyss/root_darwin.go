//go:build darwin

package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/nange/easyss/v3/log"
	"golang.org/x/sys/unix"
)

func IsRoot() bool {
	return os.Geteuid() == 0
}

// SpawnTunHelper launches a long-running elevated TUN helper process.
// It creates a FIFO for lifecycle signalling (close the writer to trigger
// helper exit) and a Unix socket for receiving the TUN file descriptor.
//
// Returns:
//   - fifoWriter: close to signal the helper to shut down
//   - fdListener: accept a connection and call ReceiveFd to get the TUN fd
func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	log.Info("[SYSTRAY] SpawnTunHelper called",
		"httpPort", httpPort, "fdSocket", fdSocketPath,
		"logFile", logFile, "logLevel", logLevel)

	exe, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("get executable: %w", err)
	}

	// Create a named FIFO for lifecycle signalling. Clean stale file first.
	fifoPath := fmt.Sprintf("/tmp/easyss-tun-ctrl-%d.fifo", os.Getpid())
	os.Remove(fifoPath) //nolint:errcheck
	if err := unix.Mkfifo(fifoPath, 0600); err != nil {
		return nil, nil, fmt.Errorf("mkfifo %s: %w", fifoPath, err)
	}

	// Open the FIFO for writing in a goroutine (blocks until the helper opens
	// it for reading via stdin redirection).
	fifoCh := openFifoForWriteAsync(fifoPath)

	// Create the Unix socket for fd passing. Clean stale socket first.
	os.Remove(fdSocketPath) //nolint:errcheck
	fdListener, err := net.Listen("unix", fdSocketPath)
	if err != nil {
		releaseFifoOpen(fifoPath, fifoCh)
		os.Remove(fifoPath) //nolint:errcheck
		return nil, nil, fmt.Errorf("listen on %s: %w", fdSocketPath, err)
	}
	// Ensure the socket is accessible by the elevated helper (root).
	os.Chmod(fdSocketPath, 0666) //nolint:errcheck

	// Build the helper command. The helper runs as the "tun-helper" subcommand,
	// reads its config via GET /tun, and sends the fd via the Unix socket.
	// Stdin is connected to the FIFO.
	tunHTTPAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)
	helperArgs := []string{
		"tun-helper",
		"--tun-http-addr", tunHTTPAddr,
		"--tun-fd-socket", fdSocketPath,
	}
	if logFile != "" {
		helperArgs = append(helperArgs, "--log-file", logFile)
	}
	if logLevel != "" {
		helperArgs = append(helperArgs, "--log-level", logLevel)
	}

	var argsBuilder strings.Builder
	for _, arg := range helperArgs {
		fmt.Fprintf(&argsBuilder, "'%s' ", strings.ReplaceAll(arg, "'", "'\\''"))
	}

	// Launch via osascript with admin privileges. The helper is backgrounded
	// (&) so osascript returns immediately; the helper stays alive monitoring
	// its stdin (the FIFO) for the main process lifecycle signal.
	cmdStr := fmt.Sprintf("'%s' %s < '%s' &>/dev/null &", exe, argsBuilder.String(), fifoPath)
	scriptCmd := strings.ReplaceAll(cmdStr, "\"", "\\\"")
	script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", scriptCmd)

	osascriptCmd := exec.Command("osascript", "-e", script)
	var osaOut, osaErr bytes.Buffer
	osascriptCmd.Stdout = &osaOut
	osascriptCmd.Stderr = &osaErr
	if err := osascriptCmd.Start(); err != nil {
		fdListener.Close() //nolint:errcheck
		releaseFifoOpen(fifoPath, fifoCh)
		os.Remove(fifoPath)     //nolint:errcheck
		os.Remove(fdSocketPath) //nolint:errcheck
		return nil, nil, fmt.Errorf("start osascript: %w", err)
	}

	// Wait for osascript in the background so an early exit (auth
	// cancelled/denied, AppleScript error) surfaces immediately with the
	// real reason instead of a blind 60s FIFO timeout.
	osaCh := make(chan error, 1)
	go func() {
		osaCh <- osascriptCmd.Wait()
	}()

	// Wait for the FIFO write end to be opened (helper opened the read end).
	// If the user cancels the admin auth dialog, or osascript itself fails,
	// this returns early with the underlying error.
	timeout = max(timeout, 10*time.Second)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case r := <-fifoCh:
			if r.err != nil {
				osascriptCmd.Process.Kill() //nolint:errcheck
				fdListener.Close()          //nolint:errcheck
				os.Remove(fifoPath)         //nolint:errcheck
				os.Remove(fdSocketPath)     //nolint:errcheck
				return nil, nil, fmt.Errorf("open fifo write: %w", r.err)
			}
			return &fifoWriter{File: r.f, path: fifoPath}, fdListener, nil
		case err := <-osaCh:
			if err == nil {
				// osascript succeeded; the helper may spawn a moment after
				// osascript returns, so keep waiting for the FIFO.
				osaCh = nil
				continue
			}
			// osascript exited with an error before the helper started
			// (e.g. user cancelled the admin dialog).
			fdListener.Close() //nolint:errcheck
			releaseFifoOpen(fifoPath, fifoCh)
			os.Remove(fifoPath)     //nolint:errcheck
			os.Remove(fdSocketPath) //nolint:errcheck
			detail := strings.TrimSpace(osaErr.String())
			if detail == "" {
				detail = strings.TrimSpace(osaOut.String())
			}
			if detail != "" {
				return nil, nil, fmt.Errorf("osascript exited before tun helper started: %v: %s", err, detail)
			}
			return nil, nil, fmt.Errorf("osascript exited before tun helper started: %w", err)
		case <-deadline.C:
			// Timeout: user probably cancelled the admin dialog or the helper
			// failed to start. Kill osascript so a late authorization cannot
			// spawn a helper against sockets that are about to be removed.
			osascriptCmd.Process.Kill() //nolint:errcheck
			fdListener.Close()          //nolint:errcheck
			releaseFifoOpen(fifoPath, fifoCh)
			os.Remove(fifoPath)     //nolint:errcheck
			os.Remove(fdSocketPath) //nolint:errcheck
			return nil, nil, fmt.Errorf("timeout waiting for tun helper (user may have cancelled)")
		}
	}
}
