//go:build linux

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

func IsRoot() bool {
	return os.Geteuid() == 0
}

func RunMeElevated(extraArgs ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// Prepare arguments
	var argsBuilder strings.Builder
	for _, arg := range os.Args[1:] {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}
	for _, arg := range extraArgs {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}

	// Capture necessary environment variables for GUI
	envMap := make(map[string]string)
	envVars := []string{"DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "HOME", "DBUS_SESSION_BUS_ADDRESS"}

	for _, key := range envVars {
		if val := os.Getenv(key); val != "" {
			envMap[key] = val
		}
	}

	// Fallback for XAUTHORITY if missing
	if _, ok := envMap["XAUTHORITY"]; !ok {
		if home, ok := envMap["HOME"]; ok {
			envMap["XAUTHORITY"] = filepath.Join(home, ".Xauthority")
		} else {
			// Try to get current user's home dir
			if homeDir, err := os.UserHomeDir(); err == nil {
				envMap["XAUTHORITY"] = filepath.Join(homeDir, ".Xauthority")
			}
		}
	}

	innerCmd := fmt.Sprintf("nohup '%s' %s >/dev/null 2>&1 &", exe, argsBuilder.String())

	cmdArgs := []string{"env"}
	for k, v := range envMap {
		cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%s", k, v))
	}
	cmdArgs = append(cmdArgs, "sh", "-c", innerCmd)

	_, err = util.Command("pkexec", cmdArgs...)
	return err
}

// SpawnTunHelper launches a long-running elevated TUN helper process via pkexec.
// It creates a FIFO for lifecycle signalling (close the writer to trigger
// helper exit) and a Unix socket for receiving the TUN file descriptor.
//
// Returns:
//   - fifoWriter: close to signal the helper to shut down
//   - fdListener: accept a connection and call ReceiveFd to get the TUN fd
func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string) (io.WriteCloser, net.Listener, error) {
	log.Info("[SYSTRAY] SpawnTunHelper called",
		"httpPort", httpPort, "fdSocket", fdSocketPath,
		"logFile", logFile, "logLevel", logLevel)

	exe, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("get executable: %w", err)
	}

	// Create a named FIFO for lifecycle signalling.
	fifoPath := fmt.Sprintf("/tmp/easyss-tun-ctrl-%d.fifo", os.Getpid())
	if err := unix.Mkfifo(fifoPath, 0600); err != nil {
		return nil, nil, fmt.Errorf("mkfifo %s: %w", fifoPath, err)
	}

	// Open the FIFO for writing in a goroutine (blocks until the helper opens
	// it for reading via stdin redirection).
	type fifoResult struct {
		f   *os.File
		err error
	}
	fifoCh := make(chan fifoResult, 1)
	go func() {
		f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
		fifoCh <- fifoResult{f, err}
	}()

	// Create the Unix socket for fd passing.
	fdListener, err := net.Listen("unix", fdSocketPath)
	if err != nil {
		// Clean up the FIFO on failure. The goroutine will unblock when we
		// remove the FIFO (open returns error).
		os.Remove(fifoPath) //nolint:errcheck
		return nil, nil, fmt.Errorf("listen on %s: %w", fdSocketPath, err)
	}

	// Build the helper command. The helper reads its config via GET /tun and
	// sends the fd via the Unix socket. Stdin is connected to the FIFO.
	tunHTTPAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)
	helperArgs := []string{
		"--tun-helper",
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
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
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
	if err := pkexecCmd.Start(); err != nil {
		fdListener.Close()      //nolint:errcheck
		os.Remove(fifoPath)     //nolint:errcheck
		os.Remove(fdSocketPath) //nolint:errcheck
		return nil, nil, fmt.Errorf("start pkexec: %w", err)
	}

	// Wait for the FIFO write end to be opened (helper opened the read end).
	// If the user cancels the pkexec auth dialog, this will time out.
	select {
	case r := <-fifoCh:
		if r.err != nil {
			fdListener.Close()      //nolint:errcheck
			os.Remove(fifoPath)     //nolint:errcheck
			os.Remove(fdSocketPath) //nolint:errcheck
			return nil, nil, fmt.Errorf("open fifo write: %w", r.err)
		}
		return r.f, fdListener, nil
	case <-time.After(60 * time.Second):
		fdListener.Close()      //nolint:errcheck
		os.Remove(fifoPath)     //nolint:errcheck
		os.Remove(fdSocketPath) //nolint:errcheck
		return nil, nil, fmt.Errorf("timeout waiting for tun helper (user may have cancelled)")
	}
}


