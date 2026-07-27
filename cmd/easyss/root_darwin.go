//go:build darwin

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nange/easyss/v3/client/tun"
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

	// Resolve config file to absolute path so the elevated helper can find it
	// even though its working directory may differ.
	resolveConfigArg(&extraArgs)

	var argsBuilder strings.Builder
	for _, arg := range os.Args[1:] {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}
	for _, arg := range extraArgs {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}

	// For macOS, we use osascript to run with admin privileges
	// We run it in background using & to avoid blocking
	cmdStr := fmt.Sprintf("'%s' %s &>/dev/null &", exe, argsBuilder.String())

	// Escape double quotes for AppleScript string
	scriptCmd := strings.ReplaceAll(cmdStr, "\"", "\\\"")
	script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", scriptCmd)

	_, err = util.Command("osascript", "-e", script)
	return err
}

// resolveConfigArg converts any relative -c path in extraArgs to absolute.
// The elevated process may have a different working directory so a relative
// config path would fail to load.
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

// SpawnTunHelper launches a short-lived elevated helper that opens the TUN
// device, sets up routing and DNS, and passes the TUN file descriptor and
// original DNS back to the parent process via a Unix domain socket.
func SpawnTunHelper(dev tun.DeviceConfig, dnsServer string) (*tunHelperResult, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("get executable: %w", err)
	}

	// Create a temporary Unix socket for fd passing.
	socketPath := fmt.Sprintf("/tmp/easyss-tun-helper-%d.sock", time.Now().UnixNano())
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	defer func() {
		listener.Close()      //nolint:errcheck
		os.Remove(socketPath) //nolint:errcheck
	}()

	// Build helper command with only tun-helper specific flags.
	helperArgs := []string{
		"--tun-helper",
		"--tun-helper-socket", socketPath,
		"--tun-helper-device", dev.Device,
		"--tun-helper-tun-ip", dev.TunIP,
		"--tun-helper-tun-gw", dev.TunGW,
		"--tun-helper-local-gateway", dev.LocalGateway,
		"--tun-helper-tun-ip-v6", dev.TunIPV6Sub,
		"--tun-helper-tun-gw-v6", dev.TunGWV6,
		"--tun-helper-server-ip-v6", dev.ServerIPV6,
		"--tun-helper-local-gateway-v6", dev.LocalGatewayV6,
		"--tun-helper-dns", dnsServer,
	}

	var argsBuilder strings.Builder
	for _, arg := range helperArgs {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}

	// Wrap in osascript with admin privileges. The helper connects to the
	// socket and exits quickly (< 2 seconds), so we run osascript in a
	// goroutine while Accept-ing concurrently.
	cmdStr := fmt.Sprintf("'%s' %s", exe, argsBuilder.String())
	scriptCmd := strings.ReplaceAll(cmdStr, "\"", "\\\"")
	script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", scriptCmd)

	resultCh := make(chan *tunHelperResult, 1)
	errCh := make(chan error, 1)

	go func() {
		if err := setAcceptDeadline(listener, 30*time.Second); err != nil {
			errCh <- fmt.Errorf("set accept deadline: %w", err)
			return
		}

		conn, err := listener.Accept()
		if err != nil {
			errCh <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close() //nolint:errcheck

		result, err := recvFdAndDNS(conn)
		if err != nil {
			errCh <- fmt.Errorf("recv fd/dns: %w", err)
			return
		}

		resultCh <- result
	}()

	// Run osascript with a timeout context so we don't block forever if
	// the user cancels the admin auth dialog.
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	if _, err := util.CommandContext(ctx, "osascript", "-e", script); err != nil {
		// If osascript fails (e.g. user cancelled), wait briefly for the
		// accept goroutine to wake up and return its error, then return
		// the osascript error as it's more informative.
		select {
		case <-errCh:
		case <-time.After(100 * time.Millisecond):
		}
		return nil, fmt.Errorf("spawn helper: %w (user may have cancelled)", err)
	}

	// Wait for the result.
	select {
	case result := <-resultCh:
		return result, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(35 * time.Second):
		return nil, fmt.Errorf("timeout waiting for tun helper")
	}
}

// setAcceptDeadline sets the accept deadline on a Unix listener.
func setAcceptDeadline(listener net.Listener, d time.Duration) error {
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		return fmt.Errorf("not a unix listener")
	}
	return unixListener.SetDeadline(time.Now().Add(d))
}

// recvFdAndDNS receives a file descriptor and original DNS info from a Unix
// domain socket connection. The fd is sent via SCM_RIGHTS followed by a
// comma-separated DNS line.
func recvFdAndDNS(conn net.Conn) (*tunHelperResult, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("not a unix connection")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("get syscall conn: %w", err)
	}

	var (
		result  *tunHelperResult
		recvErr error
	)
	err = rawConn.Read(func(fd uintptr) bool {
		// Read the fd via SCM_RIGHTS.
		buf := make([]byte, 1)
		oob := make([]byte, unix.CmsgSpace(4))
		_, oobn, _, _, err := unix.Recvmsg(int(fd), buf, oob, 0)
		if err != nil {
			recvErr = fmt.Errorf("recvmsg: %w", err)
			return false
		}

		scms, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			recvErr = fmt.Errorf("parse control message: %w", err)
			return false
		}
		if len(scms) == 0 {
			recvErr = fmt.Errorf("no control message received")
			return false
		}

		fds, err := unix.ParseUnixRights(&scms[0])
		if err != nil {
			recvErr = fmt.Errorf("parse unix rights: %w", err)
			return false
		}
		if len(fds) == 0 {
			recvErr = fmt.Errorf("no fd received")
			return false
		}

		result = &tunHelperResult{FD: fds[0]}
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("read control: %w", err)
	}
	if recvErr != nil {
		return nil, recvErr
	}

	// Read the DNS line that follows the fd.
	reader := bufio.NewReader(conn)
	dnsLine, err := reader.ReadString('\n')
	if err != nil {
		// DNS info is optional; don't fail if we can't read it.
		return result, nil
	}
	dnsLine = strings.TrimSpace(dnsLine)
	if dnsLine != "" {
		result.OriginDNS = strings.Split(dnsLine, ",")
		// Filter out empty strings (from empty DNS list).
		filtered := make([]string, 0, len(result.OriginDNS))
		for _, s := range result.OriginDNS {
			if s != "" {
				filtered = append(filtered, s)
			}
		}
		result.OriginDNS = filtered
	}

	return result, nil
}
