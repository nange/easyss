//go:build darwin || linux

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
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

func IsRoot() bool {
	return os.Geteuid() == 0
}

// tunHelperElevator abstracts how an elevated TUN helper is launched: pkexec
// on Linux, osascript with administrator privileges on macOS. The two
// platforms differ only in the elevation command, the shell line that
// backgrounds the helper, and the fd-socket lifecycle; everything else
// (FIFO lifecycle, wait loop, cleanup) is shared by spawnTunHelper.
type tunHelperElevator struct {
	// label names the elevator in error messages ("pkexec"/"osascript").
	label string
	// command builds the elevation command that runs innerCmd.
	command func(innerCmd string) *exec.Cmd
	// innerCmd builds the shell line that backgrounds the helper: it must
	// run `'<exe>' <args> < '<fifo>'` detached, with output discarded.
	innerCmd func(exe, helperArgs, fifoPath string) string
	// Socket lifecycle hooks, nil on platforms that need none (Linux uses an
	// abstract socket, which has no filesystem entry).
	beforeListen  func(fdSocketPath string)
	afterListen   func(fdSocketPath string)
	cleanupSocket func(fdSocketPath string)
}

// spawnTunHelper launches a long-running elevated TUN helper process via the
// platform elevator. It creates a FIFO for lifecycle signalling (close the
// writer to trigger helper exit) and a Unix socket for receiving the TUN file
// descriptor.
//
// Returns:
//   - fifoWriter: close to signal the helper to shut down
//   - fdListener: accept a connection and call ReceiveFd to get the TUN fd
func spawnTunHelper(ev tunHelperElevator, httpPort int, fdSocketPath, logFile, logLevel string, timeout time.Duration) (io.WriteCloser, net.Listener, error) {
	log.Info("[SYSTRAY] SpawnTunHelper called",
		"httpPort", httpPort, "fdSocket", fdSocketPath,
		"logFile", logFile, "logLevel", logLevel)

	exe, err := util.ExecutablePath()
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

	// Create the Unix socket for fd passing.
	if ev.beforeListen != nil {
		ev.beforeListen(fdSocketPath)
	}
	fdListener, err := net.Listen("unix", fdSocketPath)
	if err != nil {
		releaseFifoOpen(fifoPath, fifoCh)
		os.Remove(fifoPath) //nolint:errcheck
		return nil, nil, fmt.Errorf("listen on %s: %w", fdSocketPath, err)
	}
	if ev.afterListen != nil {
		ev.afterListen(fdSocketPath)
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

	// Launch via the elevator. The helper is backgrounded (&) so the elevator
	// returns immediately; the helper stays alive monitoring its stdin (the
	// FIFO) for the main process lifecycle signal.
	elevCmd := ev.command(ev.innerCmd(exe, util.ShellJoin(helperArgs), fifoPath))
	var elevOut, elevErr bytes.Buffer
	elevCmd.Stdout = &elevOut
	elevCmd.Stderr = &elevErr
	if err := elevCmd.Start(); err != nil {
		fdListener.Close() //nolint:errcheck
		releaseFifoOpen(fifoPath, fifoCh)
		os.Remove(fifoPath) //nolint:errcheck
		if ev.cleanupSocket != nil {
			ev.cleanupSocket(fdSocketPath)
		}
		return nil, nil, fmt.Errorf("start %s: %w", ev.label, err)
	}

	// Wait for the elevator in the background so an early exit (auth
	// cancelled/denied, elevator error) surfaces immediately with the real
	// reason instead of a blind FIFO timeout.
	elevCh := make(chan error, 1)
	go func() {
		elevCh <- elevCmd.Wait()
	}()

	// Wait for the FIFO write end to be opened (helper opened the read end).
	// If the user cancels the auth dialog, this returns early with the
	// underlying error.
	timeout = max(timeout, 10*time.Second)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case r := <-fifoCh:
			if r.err != nil {
				elevCmd.Process.Kill() //nolint:errcheck
				fdListener.Close()     //nolint:errcheck
				os.Remove(fifoPath)    //nolint:errcheck
				if ev.cleanupSocket != nil {
					ev.cleanupSocket(fdSocketPath)
				}
				return nil, nil, fmt.Errorf("open fifo write: %w", r.err)
			}
			return &fifoWriter{File: r.f, path: fifoPath}, fdListener, nil
		case err := <-elevCh:
			if err == nil {
				// The elevator succeeded; the helper may spawn a moment after
				// it returns, so keep waiting for the FIFO.
				elevCh = nil
				continue
			}
			// The elevator exited with an error before the helper started
			// (e.g. user cancelled the auth dialog).
			fdListener.Close() //nolint:errcheck
			releaseFifoOpen(fifoPath, fifoCh)
			os.Remove(fifoPath) //nolint:errcheck
			if ev.cleanupSocket != nil {
				ev.cleanupSocket(fdSocketPath)
			}
			detail := strings.TrimSpace(elevErr.String())
			if detail == "" {
				detail = strings.TrimSpace(elevOut.String())
			}
			if detail != "" {
				return nil, nil, fmt.Errorf("%s exited before tun helper started: %v: %s", ev.label, err, detail)
			}
			return nil, nil, fmt.Errorf("%s exited before tun helper started: %w", ev.label, err)
		case <-deadline.C:
			// Timeout: user probably cancelled the auth dialog or the helper
			// failed to start. Kill the elevator so a late authorization
			// cannot spawn a helper against sockets that are about to be
			// removed.
			elevCmd.Process.Kill() //nolint:errcheck
			fdListener.Close()     //nolint:errcheck
			releaseFifoOpen(fifoPath, fifoCh)
			os.Remove(fifoPath) //nolint:errcheck
			if ev.cleanupSocket != nil {
				ev.cleanupSocket(fdSocketPath)
			}
			return nil, nil, fmt.Errorf("timeout waiting for tun helper (user may have cancelled)")
		}
	}
}
