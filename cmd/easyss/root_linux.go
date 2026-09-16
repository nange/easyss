//go:build linux

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

// SpawnTunHelper launches a long-running elevated TUN helper process via pkexec.
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

	// Create the Unix socket for fd passing. On Linux we use an abstract
	// socket (@-prefixed) which does not create a filesystem entry and is
	// immune to pkexec mount namespace isolation.
	fdListener, err := net.Listen("unix", fdSocketPath)
	if err != nil {
		releaseFifoOpen(fifoPath, fifoCh)
		os.Remove(fifoPath) //nolint:errcheck
		return nil, nil, fmt.Errorf("listen on %s: %w", fdSocketPath, err)
	}

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

	// Launch via pkexec. The helper is backgrounded (&) so pkexec returns
	// immediately; the helper stays alive monitoring its stdin (the FIFO) for
	// the main process lifecycle signal.
	innerCmd := fmt.Sprintf("nohup '%s' %s < '%s' >/dev/null 2>&1 &", exe, argsBuilder.String(), fifoPath)

	// Pass HOME so the helper can find the config file; pkexec sanitizes env.
	cmdArgs := []string{"env"}
	if home := os.Getenv("HOME"); home != "" {
		cmdArgs = append(cmdArgs, fmt.Sprintf("HOME=%s", home))
	}
	cmdArgs = append(cmdArgs, "sh", "-c", innerCmd)

	pkexecCmd := exec.Command("pkexec", cmdArgs...)
	var pkexecOut, pkexecErr bytes.Buffer
	pkexecCmd.Stdout = &pkexecOut
	pkexecCmd.Stderr = &pkexecErr
	if err := pkexecCmd.Start(); err != nil {
		fdListener.Close() //nolint:errcheck
		releaseFifoOpen(fifoPath, fifoCh)
		os.Remove(fifoPath) //nolint:errcheck
		return nil, nil, fmt.Errorf("start pkexec: %w", err)
	}

	// Wait for pkexec in the background so an early exit (auth
	// cancelled/denied, pkexec error) surfaces immediately with the real
	// reason instead of a blind 60s FIFO timeout.
	pkexecCh := make(chan error, 1)
	go func() {
		pkexecCh <- pkexecCmd.Wait()
	}()

	// Wait for the FIFO write end to be opened (helper opened the read end).
	// If the user cancels the pkexec auth dialog, this returns early with
	// the underlying error.
	timeout = max(timeout, 10*time.Second)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case r := <-fifoCh:
			if r.err != nil {
				pkexecCmd.Process.Kill() //nolint:errcheck
				fdListener.Close()       //nolint:errcheck
				os.Remove(fifoPath)      //nolint:errcheck
				return nil, nil, fmt.Errorf("open fifo write: %w", r.err)
			}
			return &fifoWriter{File: r.f, path: fifoPath}, fdListener, nil
		case err := <-pkexecCh:
			if err == nil {
				// pkexec succeeded; the helper may spawn a moment after
				// pkexec returns, so keep waiting for the FIFO.
				pkexecCh = nil
				continue
			}
			// pkexec exited with an error before the helper started
			// (e.g. user cancelled the auth dialog).
			fdListener.Close() //nolint:errcheck
			releaseFifoOpen(fifoPath, fifoCh)
			os.Remove(fifoPath) //nolint:errcheck
			detail := strings.TrimSpace(pkexecErr.String())
			if detail == "" {
				detail = strings.TrimSpace(pkexecOut.String())
			}
			if detail != "" {
				return nil, nil, fmt.Errorf("pkexec exited before tun helper started: %v: %s", err, detail)
			}
			return nil, nil, fmt.Errorf("pkexec exited before tun helper started: %w", err)
		case <-deadline.C:
			// Timeout: user probably cancelled the auth dialog or the helper
			// failed to start. Kill pkexec so a late authorization cannot
			// spawn a helper against sockets that are about to be removed.
			pkexecCmd.Process.Kill() //nolint:errcheck
			fdListener.Close()       //nolint:errcheck
			releaseFifoOpen(fifoPath, fifoCh)
			os.Remove(fifoPath) //nolint:errcheck
			return nil, nil, fmt.Errorf("timeout waiting for tun helper (user may have cancelled)")
		}
	}
}
