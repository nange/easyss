//go:build darwin

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/scripts"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

const utunControlName = "com.apple.net.utun_control"

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

	// 1. Initialize logger as early as possible so all errors are visible
	//    in the log file (not lost to /dev/null via stderr).
	log.Init(logFilePath, logLevel)

	// 2. Fetch TUN configuration from the main process via HTTP.
	cfg, err := fetchTunConfig(httpAddr)
	if err != nil {
		log.Error("[TUN-HELPER] fetch tun config", "err", err)
		return 1
	}
	log.Info("[TUN-HELPER] config received", "device", cfg.Device)

	// 3. Acquire an exclusive file lock to ensure only one helper runs at a
	//    time. If a previous helper is still cleaning up, we block until it
	//    exits and the kernel releases the lock (works even with kill -9).
	lockFile, err := os.OpenFile("/tmp/easyss-tun.lock", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		log.Error("[TUN-HELPER] open lock file", "err", err)
		return 1
	}
	if err := flockWait(lockFile, 30*time.Second); err != nil {
		log.Error("[TUN-HELPER] acquire lock", "err", err)
		lockFile.Close() //nolint:errcheck
		return 1
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
		log.Error("[TUN-HELPER] open tun device", "device", cfg.Device, "err", err)
		return 1
	}
	log.Info("[TUN-HELPER] device created", "requested", cfg.Device, "actual", actualDevice)

	// Defer cleanup: on exit, remove routes and restore DNS.
	defer func() {
		log.Info("[TUN-HELPER] cleaning up routes and DNS")
		_ = runCloseScript(actualDevice, cfg.TunGW, cfg.LocalGateway,
			cfg.TunGWV6, cfg.ServerIPV6, cfg.LocalGatewayV6)
		_ = restoreDNS(originDNS)
		log.Info("[TUN-HELPER] cleanup done")
	}()

	// Give the kernel a brief moment to initialize the interface.
	log.Info("[TUN-HELPER] waiting for kernel interface init")
	time.Sleep(200 * time.Millisecond)

	// 6. Clean up any stale routes from a previous TUN session.
	log.Info("[TUN-HELPER] cleaning stale routes")
	_ = runCloseScript(actualDevice, cfg.TunGW, cfg.LocalGateway,
		cfg.TunGWV6, cfg.ServerIPV6, cfg.LocalGatewayV6)

	// 7. Run the create script (ifconfig + route add).
	log.Info("[TUN-HELPER] creating routes and configuring interface")
	if err := runCreateScript(actualDevice, cfg.TunIP, cfg.TunGW, cfg.LocalGateway,
		cfg.TunIPV6Sub, cfg.TunGWV6, cfg.ServerIPV6, cfg.LocalGatewayV6); err != nil {
		log.Error("[TUN-HELPER] run create script", "err", err)
		_ = unix.Close(tunFd)
		return 1
	}
	log.Info("[TUN-HELPER] routes and interface configured")

	// 8. Set system DNS.
	if cfg.DNSAddr != "" {
		log.Info("[TUN-HELPER] setting system dns", "dns", cfg.DNSAddr)
		if err := util.SetSysDNS([]string{cfg.DNSAddr}); err != nil {
			log.Warn("[TUN-HELPER] set dns", "err", err)
		}
	}

	// 9. Send the TUN fd to the main process via Unix domain socket.
	log.Info("[TUN-HELPER] sending tun fd to parent", "socket", fdSocketPath)
	if err := sendFdToParent(fdSocketPath, tunFd); err != nil {
		log.Error("[TUN-HELPER] send fd to parent", "err", err)
		_ = unix.Close(tunFd)
		return 1
	}

	// 10. Close the fd (it has been sent to the parent).
	_ = unix.Close(tunFd)
	log.Info("[TUN-HELPER] fd sent and closed")

	log.Info("[TUN-HELPER] ready, waiting for shutdown signal on stdin")

	// 11. Block reading stdin until EOF. The main process closes the FIFO
	//     write end to signal shutdown, or the kernel closes it if the main
	//     process crashes (even on kill -9).
	_, _ = io.ReadAll(os.Stdin)

	log.Info("[TUN-HELPER] received shutdown signal")
	return 0
}

// fetchTunConfig retrieves the TUN configuration from the main process via
// GET /tun. It retries with backoff for up to 10 seconds in case the HTTP
// server is not ready yet.
func fetchTunConfig(httpAddr string) (*proxy.TunConfig, error) {
	url := fmt.Sprintf("http://%s/tun", httpAddr)

	var lastErr error
	for i := 0; i < 10; i++ {
		if i > 0 {
			time.Sleep(time.Duration(i) * 200 * time.Millisecond)
		}

		resp, err := http.Get(url) //nolint:gosec
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close() //nolint:errcheck

		if resp.StatusCode == http.StatusServiceUnavailable {
			lastErr = fmt.Errorf("tun not configured yet (503)")
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			lastErr = fmt.Errorf("GET /tun returned %d: %s", resp.StatusCode, string(body))
			continue
		}

		var cfg proxy.TunConfig
		if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
			lastErr = fmt.Errorf("decode tun config: %w", err)
			continue
		}

		return &cfg, nil
	}

	return nil, fmt.Errorf("fetch tun config after retries: %w", lastErr)
}

// openTunDevice creates a TUN device on macOS using the SYSPROTO_CONTROL
// kernel control socket mechanism. It returns the raw file descriptor and
// the actual interface name assigned by the kernel.
func openTunDevice(name string) (int, string, error) {
	ifIndex := -1
	if name != "utun" {
		_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
			return -1, "", fmt.Errorf("invalid interface name %q: must be utun[0-9]*", name)
		}
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		return -1, "", fmt.Errorf("socket(AF_SYSTEM): %w", err)
	}

	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], []byte(utunControlName))
	if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		unix.Close(fd) //nolint:errcheck
		return -1, "", fmt.Errorf("ioctl CTLIOCGINFO: %w", err)
	}

	sc := &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(ifIndex) + 1,
	}
	if err := unix.Connect(fd, sc); err != nil {
		unix.Close(fd) //nolint:errcheck
		return -1, "", fmt.Errorf("connect utun control: %w", err)
	}

	actualName, err := unix.GetsockoptString(fd, 2, 2)
	if err != nil {
		unix.Close(fd) //nolint:errcheck
		return -1, "", fmt.Errorf("getsockopt UTUN_OPT_IFNAME: %w", err)
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd) //nolint:errcheck
		return -1, "", fmt.Errorf("set nonblock: %w", err)
	}

	return fd, actualName, nil
}

// runCreateScript writes the embedded create_tun_dev_darwin.sh to a temp file
// and executes it with the device configuration.
func runCreateScript(device, tunIP, tunGW, localGateway,
	tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6 string) error {
	if scripts.CreateTunBytes == nil {
		return fmt.Errorf("no create script for darwin")
	}

	namePath, err := util.WriteToTemp(scripts.CreateTunFilename, scripts.CreateTunBytes)
	if err != nil {
		return fmt.Errorf("write create script: %w", err)
	}
	defer os.RemoveAll(filepath.Dir(namePath)) //nolint:errcheck

	_, err = util.Command("sh", namePath, device, tunIP, tunGW, localGateway,
		tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6)
	if err != nil {
		return fmt.Errorf("exec create script: %w", err)
	}
	return nil
}

// runCloseScript writes the embedded close_tun_dev_darwin.sh to a temp file
// and executes it. Errors are ignored since this is best-effort cleanup.
func runCloseScript(device, tunGW, localGateway, tunGWV6, serverIPV6, localGatewayV6 string) error {
	if scripts.CloseTunBytes == nil {
		return nil
	}

	namePath, err := util.WriteToTemp(scripts.CloseTunFilename, scripts.CloseTunBytes)
	if err != nil {
		return nil
	}
	defer os.RemoveAll(filepath.Dir(namePath)) //nolint:errcheck

	_, _ = util.Command("sh", namePath, device, tunGW, localGateway, tunGWV6, serverIPV6, localGatewayV6)
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

// restoreDNS restores the system DNS to the original servers.
func restoreDNS(originDNS []string) error {
	if len(originDNS) == 0 {
		return util.SetSysDNS([]string{"empty"})
	}
	curr, err := util.SysDNS()
	if err != nil {
		return err
	}
	if !stringSliceEqual(originDNS, curr) {
		return util.SetSysDNS(originDNS)
	}
	return nil
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
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
