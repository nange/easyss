//go:build darwin

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

	// Resolve config file to absolute path so the elevated process can find it.
	resolveConfigArg(&extraArgs)

	var argsBuilder strings.Builder
	for _, arg := range os.Args[1:] {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}
	for _, arg := range extraArgs {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}

	cmdStr := fmt.Sprintf("'%s' %s &>/dev/null &", exe, argsBuilder.String())

	scriptCmd := strings.ReplaceAll(cmdStr, "\"", "\\\"")
	script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", scriptCmd)

	_, err = util.Command("osascript", "-e", script)
	return err
}

// resolveConfigArg converts any relative -c path in extraArgs to absolute.
func resolveConfigArg(extraArgs *[]string) {
	args := *extraArgs
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-c" && !filepath.IsAbs(args[i+1]) {
			if abs, err := filepath.Abs(args[i+1]); err == nil {
				args[i+1] = abs
			}
		}
	}
	*extraArgs = args
}

// SpawnTunHelper launches a long-running elevated TUN helper process.
// It creates a FIFO for lifecycle signalling (close the writer to trigger
// helper shutdown) and a Unix socket for receiving the TUN file descriptor.
//
// Returns:
//   - cmd: the osascript process handle
//   - fifoWriter: close to signal the helper to shut down
//   - fdListener: accept a connection and call ReceiveFd to get the TUN fd
func SpawnTunHelper(httpPort int, fdSocketPath, logFile, logLevel string) (*exec.Cmd, io.WriteCloser, net.Listener, error) {
	log.Info("[SYSTRAY] SpawnTunHelper called",
		"httpPort", httpPort, "fdSocket", fdSocketPath,
		"logFile", logFile, "logLevel", logLevel)

	exe, err := os.Executable()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get executable: %w", err)
	}

	// Create a named FIFO for lifecycle signalling.
	fifoPath := fmt.Sprintf("/tmp/easyss-tun-ctrl-%d.fifo", os.Getpid())
	if err := unix.Mkfifo(fifoPath, 0600); err != nil {
		return nil, nil, nil, fmt.Errorf("mkfifo %s: %w", fifoPath, err)
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
		return nil, nil, nil, fmt.Errorf("listen on %s: %w", fdSocketPath, err)
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

	// Launch via osascript with admin privileges. The helper is backgrounded
	// (&) so osascript returns immediately; the helper stays alive monitoring
	// its stdin (the FIFO) for the main process lifecycle signal.
	cmdStr := fmt.Sprintf("'%s' %s < '%s' &>/dev/null &", exe, argsBuilder.String(), fifoPath)
	scriptCmd := strings.ReplaceAll(cmdStr, "\"", "\\\"")
	script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", scriptCmd)

	osascriptCmd := exec.Command("osascript", "-e", script)
	if err := osascriptCmd.Start(); err != nil {
		fdListener.Close()      //nolint:errcheck
		os.Remove(fifoPath)     //nolint:errcheck
		os.Remove(fdSocketPath) //nolint:errcheck
		return nil, nil, nil, fmt.Errorf("start osascript: %w", err)
	}

	// Wait for the FIFO write end to be opened (helper opened the read end).
	// If the user cancels the admin auth dialog, this will time out.
	select {
	case r := <-fifoCh:
		if r.err != nil {
			fdListener.Close()      //nolint:errcheck
			os.Remove(fifoPath)     //nolint:errcheck
			os.Remove(fdSocketPath) //nolint:errcheck
			return nil, nil, nil, fmt.Errorf("open fifo write: %w", r.err)
		}
		return osascriptCmd, r.f, fdListener, nil
	case <-time.After(60 * time.Second):
		// Timeout: user probably cancelled the admin dialog or the helper
		// failed to start. Clean up and return an error.
		fdListener.Close()      //nolint:errcheck
		os.Remove(fifoPath)     //nolint:errcheck
		os.Remove(fdSocketPath) //nolint:errcheck
		return nil, nil, nil, fmt.Errorf("timeout waiting for tun helper (user may have cancelled)")
	}
}

// ReceiveFd accepts a single connection on the Unix domain socket listener and
// receives a file descriptor via SCM_RIGHTS. It does not read any data from
// the connection — the fd is passed purely as ancillary data.
func ReceiveFd(listener net.Listener) (int, error) {
	if err := setAcceptDeadline(listener, 30*time.Second); err != nil {
		return -1, fmt.Errorf("set accept deadline: %w", err)
	}

	conn, err := listener.Accept()
	if err != nil {
		return -1, fmt.Errorf("accept: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("not a unix connection")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("get syscall conn: %w", err)
	}

	var (
		result  int
		recvErr error
	)
	ctrlErr := rawConn.Control(func(fd uintptr) {
		// Switch to blocking mode so Recvmsg waits for data.
		if err := unix.SetNonblock(int(fd), false); err != nil {
			recvErr = fmt.Errorf("set blocking: %w", err)
			return
		}
		defer unix.SetNonblock(int(fd), true) //nolint:errcheck

		buf := make([]byte, 1)
		oob := make([]byte, unix.CmsgSpace(4))
		_, oobn, _, _, err := unix.Recvmsg(int(fd), buf, oob, 0)
		if err != nil {
			recvErr = fmt.Errorf("recvmsg: %w", err)
			return
		}

		scms, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			recvErr = fmt.Errorf("parse control message: %w", err)
			return
		}
		if len(scms) == 0 {
			recvErr = fmt.Errorf("no control message received")
			return
		}

		fds, err := unix.ParseUnixRights(&scms[0])
		if err != nil {
			recvErr = fmt.Errorf("parse unix rights: %w", err)
			return
		}
		if len(fds) == 0 {
			recvErr = fmt.Errorf("no fd received")
			return
		}

		result = fds[0]
	})
	if ctrlErr != nil {
		return -1, fmt.Errorf("control: %w", ctrlErr)
	}
	if recvErr != nil {
		return -1, recvErr
	}

	return result, nil
}

// setAcceptDeadline sets the accept deadline on a Unix listener.
func setAcceptDeadline(listener net.Listener, d time.Duration) error {
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		return fmt.Errorf("not a unix listener")
	}
	return unixListener.SetDeadline(time.Now().Add(d))
}
