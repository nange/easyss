//go:build darwin

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/scripts"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

const utunControlName = "com.apple.net.utun_control"

// runTunHelper is the entry point for the short-lived elevated TUN helper.
// It opens the TUN device, sets up routing/DNS, passes the fd and original
// DNS back to the parent process via a Unix domain socket, and exits.
func runTunHelper(socketPath, device, tunIP, tunGW, localGateway,
	tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6, dnsServer string) int {

	if socketPath == "" || device == "" {
		log.Error("[TUN-HELPER] missing required flags")
		return 1
	}

	// 1. Save the original system DNS before changing it.
	originDNS, err := util.SysDNS()
	if err != nil {
		log.Warn("[TUN-HELPER] read original dns", "err", err)
	}

	// 2. Open the TUN device.
	tunFd, actualDevice, err := openTunDevice(device)
	if err != nil {
		log.Error("[TUN-HELPER] open tun device", "device", device, "err", err)
		return 1
	}
	log.Info("[TUN-HELPER] device created", "requested", device, "actual", actualDevice)

	// Give the kernel a brief moment to initialize the interface.
	time.Sleep(200 * time.Millisecond)

	// 3. Run the create script (ifconfig + route add).
	if err := runCreateScript(actualDevice, tunIP, tunGW, localGateway,
		tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6); err != nil {
		log.Error("[TUN-HELPER] run create script", "err", err)
		_ = unix.Close(tunFd)
		return 1
	}

	// 4. Set system DNS.
	if dnsServer != "" {
		if err := util.SetSysDNS([]string{dnsServer}); err != nil {
			log.Warn("[TUN-HELPER] set dns", "err", err)
		}
	}

	// 5. Connect to the parent's socket and send the fd + original DNS.
	if err := sendFdToParent(socketPath, tunFd, originDNS); err != nil {
		log.Error("[TUN-HELPER] send fd to parent", "err", err)
		_ = unix.Close(tunFd)
		return 1
	}

	// 6. Close the fd (it's been sent to the parent).
	_ = unix.Close(tunFd)

	log.Info("[TUN-HELPER] done")
	return 0
}

// openTunDevice creates a TUN device on macOS using the SYSPROTO_CONTROL
// kernel control socket mechanism. It returns the raw file descriptor and
// the actual interface name assigned by the kernel.
func openTunDevice(name string) (int, string, error) {
	// Parse the unit number from the device name (e.g. "utun9" → 9).
	ifIndex := -1
	if name != "utun" {
		_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
			return -1, "", fmt.Errorf("invalid interface name %q: must be utun[0-9]*", name)
		}
	}

	// 1. Open a kernel control socket (AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL=2).
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		return -1, "", fmt.Errorf("socket(AF_SYSTEM): %w", err)
	}

	// 2. Resolve the utun kernel control ID.
	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], []byte(utunControlName))
	if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		unix.Close(fd) //nolint:errcheck
		return -1, "", fmt.Errorf("ioctl CTLIOCGINFO: %w", err)
	}

	// 3. Connect to the utun control — this creates the utunN interface.
	sc := &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(ifIndex) + 1,
	}
	if err := unix.Connect(fd, sc); err != nil {
		unix.Close(fd) //nolint:errcheck
		return -1, "", fmt.Errorf("connect utun control: %w", err)
	}

	// 4. Query the actual interface name the kernel assigned (may differ
	//    from the requested name if the unit was already in use).
	actualName, err := unix.GetsockoptString(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */)
	if err != nil {
		unix.Close(fd) //nolint:errcheck
		return -1, "", fmt.Errorf("getsockopt UTUN_OPT_IFNAME: %w", err)
	}

	// 5. Set non-blocking mode.
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

// sendFdToParent connects to the Unix socket at socketPath, sends the TUN
// file descriptor via SCM_RIGHTS, and then writes the original DNS servers
// as a comma-separated line.
func sendFdToParent(socketPath string, tunFd int, originDNS []string) error {
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

	// Send fd via SCM_RIGHTS with a single byte payload.
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

	// Write original DNS as a comma-separated line after the fd.
	dnsLine := strings.Join(originDNS, ",") + "\n"
	if _, err := conn.Write([]byte(dnsLine)); err != nil {
		return fmt.Errorf("write dns: %w", err)
	}

	return nil
}
