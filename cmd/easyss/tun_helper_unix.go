//go:build darwin || linux

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

// fifoOpenResult carries the outcome of a blocking FIFO write-open.
type fifoOpenResult struct {
	f   *os.File
	err error
}

// openFifoForWriteAsync opens fifoPath for writing in the background: open(2)
// on a FIFO blocks until a reader appears, and the reader here is the elevated
// helper started via stdin redirection.
func openFifoForWriteAsync(fifoPath string) <-chan fifoOpenResult {
	ch := make(chan fifoOpenResult, 1)
	go func() {
		f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
		ch <- fifoOpenResult{f: f, err: err}
	}()
	return ch
}

// releaseFifoOpen unblocks a write-open started by openFifoForWriteAsync and
// closes the file it produced. Callers that abandon the wait must use it:
// deleting the FIFO does not unblock an open(2) that is already waiting for a
// reader, so the goroutine (and its file descriptor) would otherwise leak for
// the lifetime of the process. Opening the read end here lets the pending open
// complete; it is non-blocking and needs no writer.
func releaseFifoOpen(fifoPath string, ch <-chan fifoOpenResult) {
	rd, err := os.OpenFile(fifoPath, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	select {
	case r := <-ch:
		if r.f != nil {
			_ = r.f.Close()
		}
	case <-time.After(time.Second):
	}
	_ = rd.Close()
}

// runTunHelper is the entry point for the long-running elevated TUN helper.
// It fetches configuration from the main process via GET /tun, opens the TUN
// device, sets up routing and DNS, sends the file descriptor back via a Unix
// domain socket, then blocks reading stdin. When stdin returns EOF (main
// process closed the FIFO or crashed), it cleans up and exits.
func runTunHelper(httpAddr, fdSocketPath, logFilePath, logLevel string) int {
	if httpAddr == "" || fdSocketPath == "" {
		fmt.Fprintf(os.Stderr, "[TUN-HELPER] missing required flags\n")
		return 1
	}

	// The parent blocks in ReceiveFd until a helper connects to the fd socket,
	// so a helper that gives up before it can send a fd has to knock on that
	// socket itself: left alone, the parent would sit out its whole accept
	// deadline and report a timeout 30s later instead of the failure that just
	// happened. The reason travels on that same connection, so the tray can
	// show it instead of sending the user to the log file. Deferred, so every
	// early return below is covered, including the ones added later; a helper
	// that sent its fd stays silent.
	var (
		fdSent  bool
		failure error
	)
	defer func() {
		if !fdSent {
			notifyStartFailure(fdSocketPath, failure)
		}
	}()

	// giveUp records why the helper is exiting, logs it and returns the exit
	// code. The recorded reason is what notifyStartFailure hands to the parent.
	giveUp := func(step string, err error) int {
		failure = fmt.Errorf("%s: %w", step, err)
		log.Error("[TUN-HELPER] "+step, "err", err)
		return 1
	}

	// 1. Initialize logger as early as possible so all errors are visible
	//    in the log file (not lost to /dev/null via stderr).
	log.Init(logFilePath, logLevel)

	// 2. Fetch TUN configuration from the main process via HTTP.
	cfg, err := fetchTunConfig(httpAddr)
	if err != nil {
		return giveUp("fetch tun config", err)
	}
	log.Info("[TUN-HELPER] config received", "device", cfg.Device)

	// 3. Acquire an exclusive file lock to ensure only one helper runs at a
	//    time. If a previous helper is still cleaning up, we block until it
	//    exits and the kernel releases the lock (works even with kill -9).
	lockFile, err := os.OpenFile("/tmp/easyss-tun.lock", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return giveUp("open lock file", err)
	}
	if err := flockWait(lockFile, 30*time.Second); err != nil {
		lockFile.Close() //nolint:errcheck
		return giveUp("acquire lock", err)
	}
	log.Info("[TUN-HELPER] lock acquired")
	defer lockFile.Close() //nolint:errcheck

	// 4. Save the original system DNS before changing it.
	originDNS, err := util.SysDNS()
	if err != nil {
		log.Warn("[TUN-HELPER] read original dns", "err", err)
	}
	log.Info("[TUN-HELPER] original dns saved", "dns", originDNS)

	// 5. Open the TUN device.
	tunFd, actualDevice, err := openTunDevice(cfg.Device)
	if err != nil {
		return giveUp("open tun device", err)
	}
	log.Info("[TUN-HELPER] device created", "requested", cfg.Device, "actual", actualDevice)

	// Defer cleanup: on exit, remove routes and restore DNS.
	defer func() {
		log.Info("[TUN-HELPER] cleaning up routes and DNS")
		_ = runCloseScript(actualDevice, cfg.TunGW, cfg.LocalGateway,
			cfg.TunGWV6, cfg.ServerIPV6, cfg.LocalGatewayV6)
		removeLeftoverDevice(actualDevice)
		_ = util.RestoreSysDNSForTun(actualDevice, originDNS)
		log.Info("[TUN-HELPER] cleanup done")
	}()

	// Give the kernel a brief moment to initialize the interface.
	log.Info("[TUN-HELPER] waiting for kernel interface init")
	time.Sleep(200 * time.Millisecond)

	// 6. Clean up any stale routes from a previous TUN session.
	log.Info("[TUN-HELPER] cleaning stale routes")
	_ = runCloseScript(actualDevice, cfg.TunGW, cfg.LocalGateway,
		cfg.TunGWV6, cfg.ServerIPV6, cfg.LocalGatewayV6)

	// 7. Run the create script (ifconfig/ip + route add).
	log.Info("[TUN-HELPER] creating routes and configuring interface")
	if err := runCreateScript(actualDevice, cfg.TunIP, cfg.TunGW, cfg.LocalGateway,
		cfg.TunIPV6Sub, cfg.TunGWV6, cfg.ServerIPV6, cfg.LocalGatewayV6); err != nil {
		_ = unix.Close(tunFd)
		return giveUp("run create script", err)
	}
	log.Info("[TUN-HELPER] routes and interface configured")

	// 8. Set system DNS.
	if cfg.DNSAddr != "" {
		log.Info("[TUN-HELPER] setting system dns", "dns", cfg.DNSAddr)
		if err := util.SetSysDNSForTun(actualDevice, []string{cfg.DNSAddr}); err != nil {
			log.Warn("[TUN-HELPER] set dns", "err", err)
		}
	}

	// 9. Send the TUN fd to the main process via Unix domain socket.
	log.Info("[TUN-HELPER] sending tun fd to parent", "socket", fdSocketPath)
	if err := sendFdToParent(fdSocketPath, tunFd); err != nil {
		_ = unix.Close(tunFd)
		return giveUp("send fd to parent", err)
	}
	fdSent = true

	// 10. Close the fd (it has been sent to the parent).
	_ = unix.Close(tunFd)
	log.Info("[TUN-HELPER] fd sent and closed")

	log.Info("[TUN-HELPER] ready, waiting for shutdown signal on stdin")

	// 11. Block reading stdin until EOF. The main process closes the FIFO
	//     write end to signal shutdown, or the kernel closes it if the main
	//     process crashes (even on kill -9).
	//
	//     While waiting, periodically verify the TUN routes are still in
	//     place: macOS may clear non-persistent routes after sleep/wake or
	//     network changes, which silently disables TUN mode (traffic stops
	//     entering the device). The old tun-only daemon re-added routes
	//     every 10s to survive sleep/wake (ba6c894); the ephemeral helper
	//     keeps that behavior for the TUN routes themselves.
	stdinDone := make(chan struct{})
	go func() {
		_, _ = io.ReadAll(os.Stdin)
		close(stdinDone)
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stdinDone:
			log.Info("[TUN-HELPER] received shutdown signal")
			return 0
		case <-ticker.C:
			if err := ensureTunRoutes(actualDevice, cfg); err != nil {
				log.Warn("[TUN-HELPER] route keep-alive check failed", "device", actualDevice, "err", err)
			}
			// NetworkManager rewrites the link DNS settings when the connection
			// changes and can hand the DNS default route back to the physical
			// link, which lets resolution bypass the tunnel again.
			if cfg.DNSAddr != "" {
				if err := util.EnsureSysDNSForTun(actualDevice, []string{cfg.DNSAddr}); err != nil {
					log.Warn("[TUN-HELPER] dns keep-alive check failed", "device", actualDevice, "err", err)
				}
			}
		}
	}
}

// tunRouteProbes are destinations that must be covered by the TUN routes,
// used to verify the routes are still present after sleep/wake or network
// changes. The darwin/linux/Windows create scripts route 1.0.0.0/8 (and
// everything up to 128.0.0.0/1) through the TUN device, so 1.1.1.1 — a real,
// widely used DNS/HTTPS destination — has to resolve to it. If these probes
// and the scripts ever drift apart, the keep-alive would report a failure
// forever, so tun_helper_linux_test.go asserts that every probe falls inside
// a route block defined by the create scripts.
var tunRouteProbes = []string{"1.1.1.1"}

// probeRoutedViaDevice looks every address in probe up with cmd and reports
// whether any of them resolves through the TUN device: a covered address
// resolves to the TUN device while TUN routes are in place, never to the
// physical default route, so the lookup output must contain marker (the
// device name). The last lookup's output and error are returned so the caller
// can log why the check failed.
func probeRoutedViaDevice(probe []string, cmd func(string) (string, error), marker string) (string, error) {
	var (
		out      string
		err      error
		lastAddr string
	)
	for _, addr := range probe {
		out, err = cmd(addr)
		if err == nil && strings.Contains(out, marker) {
			return out, nil
		}
		lastAddr = addr
	}
	if err == nil {
		err = fmt.Errorf("no probe resolved via %q (last %s)", marker, lastAddr)
	}
	return out, err
}

// fetchTunConfig retrieves the TUN configuration from the main process via
// GET /tun. It retries with backoff for up to 10 seconds in case the HTTP
// server is not ready yet.
func fetchTunConfig(httpAddr string) (*proxy.TunConfig, error) {
	url := fmt.Sprintf("http://%s/tun", httpAddr)

	var lastErr error
	for i := range 10 {
		if i > 0 {
			time.Sleep(time.Duration(i) * 200 * time.Millisecond)
		}

		resp, err := http.Get(url) //nolint:gosec
		if err != nil {
			lastErr = err
			continue
		}
		// Close the body on every iteration: the retry loop can run up to ten
		// times, so a deferred close would keep every earlier response open
		// until the function returns.
		if resp.StatusCode == http.StatusServiceUnavailable {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("tun not configured yet (503)")
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("GET /tun returned %d: %s", resp.StatusCode, string(body))
			continue
		}

		var cfg proxy.TunConfig
		decodeErr := json.NewDecoder(resp.Body).Decode(&cfg)
		_ = resp.Body.Close()
		if decodeErr != nil {
			lastErr = fmt.Errorf("decode tun config: %w", decodeErr)
			continue
		}

		return &cfg, nil
	}

	// The retrying is what this error adds: the caller names the step.
	return nil, fmt.Errorf("after retries: %w", lastErr)
}

// maxHelperFailureReason caps the failure text the helper hands to the parent:
// it ends up in a desktop notification, and a platform script can fail with
// pages of quoted command output.
const maxHelperFailureReason = 512

// notifyStartFailure tells the parent, which is waiting in ReceiveFd, that this
// helper is giving up before it could send a fd, and why. Connecting to the
// socket is the signal — the parent accepts the connection and finds no fd in
// it — and the reason travels as the payload of that same connection, so the
// tray can name the failed step instead of pointing at the log file. Best
// effort: when the parent is gone there is nobody left to tell.
func notifyStartFailure(socketPath string, reason error) {
	if socketPath == "" {
		return
	}
	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		return
	}
	defer conn.Close() //nolint:errcheck

	if payload := failurePayload(reason); len(payload) > 0 {
		_, _ = conn.Write(payload)
	}
}

// failurePayload renders reason as the single line the parent shows: a desktop
// notification does not render the newlines a failed platform script produces,
// and one message is all this socket carries. Text over the cap keeps both ends
// — the failing step at the front, the script's "failed near:" summary at the
// back — and drops the repeated output in the middle.
func failurePayload(reason error) []byte {
	if reason == nil {
		return nil
	}
	msg := strings.Join(strings.Fields(reason.Error()), " ")
	if len(msg) > maxHelperFailureReason {
		const ellipsis = " ... "
		keep := maxHelperFailureReason - len(ellipsis)
		msg = msg[:keep/2] + ellipsis + msg[len(msg)-(keep-keep/2):]
	}
	return []byte(msg)
}

// execScriptWithOutput runs a platform script and returns the script's own
// output with the error. util.Command packs the whole command line and a
// Go-quoted copy of that output into its error, which is fine for a log line
// but not for what the parent shows the user: the unix create scripts name the
// step that failed in their output, and that text has to survive (see
// failurePayload).
//
// The error carries no action of its own ("run create script", say): its caller
// already names the step it was running through giveUp, and repeating it only
// makes the notification longer.
func execScriptWithOutput(shell, scriptPath string, args ...string) error {
	out, err := exec.Command(shell, append([]string{scriptPath}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// sendFdToParent connects to the Unix socket at socketPath and sends the TUN
// file descriptor via SCM_RIGHTS.
func sendFdToParent(socketPath string, tunFd int) error {
	conn, err := net.DialTimeout("unix", socketPath, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial socket %s: %w", socketPath, err)
	}
	defer conn.Close() //nolint:errcheck

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get syscall conn: %w", err)
	}

	var sendErr error
	err = rawConn.Write(func(fd uintptr) bool {
		rights := unix.UnixRights(tunFd)
		err := unix.Sendmsg(int(fd), []byte{1}, rights, nil, 0)
		if err != nil {
			sendErr = fmt.Errorf("sendmsg: %w", err)
		}
		return err == nil
	})
	if err != nil {
		return fmt.Errorf("write control: %w", err)
	}
	if sendErr != nil {
		return sendErr
	}

	log.Info("[TUN-HELPER] fd sent via unix socket", "socket", socketPath)
	return nil
}

// flockWait acquires an exclusive lock on f, retrying until the lock is
// acquired or the timeout expires. The lock is automatically released by
// the kernel when the process exits, including on kill -9.
func flockWait(f *os.File, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for lock after %v", timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// fifoWriter wraps the FIFO write end and removes the FIFO file when closed,
// so stale files never accumulate on retry or toggle-off. The FIFO is used
// for lifecycle signalling: closing the writer (EOF) tells the helper to exit.
type fifoWriter struct {
	*os.File
	path string
}

func (w *fifoWriter) Close() error {
	err := w.File.Close()
	os.Remove(w.path) //nolint:errcheck
	return err
}

// ReceiveFd accepts a single connection on the Unix domain socket listener and
// receives a file descriptor via SCM_RIGHTS. The fd is passed purely as
// ancillary data; the only payload this socket carries is the failure reason of
// a helper that gave up before it had one to send (see notifyStartFailure).
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

		// The buffer holds the failure reason notifyStartFailure may send
		// instead of a fd (see maxHelperFailureReason).
		buf := make([]byte, maxHelperFailureReason)
		oob := make([]byte, unix.CmsgSpace(4))
		n, oobn, _, _, err := unix.Recvmsg(int(fd), buf, oob, 0)
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
			// A helper that gave up connects without a fd to report exactly
			// that, and writes why: the reason is what the tray has to show.
			if reason := strings.TrimSpace(string(buf[:n])); reason != "" {
				recvErr = fmt.Errorf("the tun helper exited: %s", reason)
				return
			}
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

		// Keep the TUN fd out of any child process: the client execs pkexec
		// (which execs the next helper) while it may still hold this fd, and
		// an inherited copy keeps the interface attached, so the helper's
		// cleanup and the next start fail with "device or resource busy".
		unix.CloseOnExec(fds[0])

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
