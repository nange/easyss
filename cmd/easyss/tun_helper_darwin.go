//go:build darwin

package main

import (
	"fmt"
	"os"

	"github.com/nange/easyss/v3/scripts"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

const utunControlName = "com.apple.net.utun_control"

// tunFdSocketPath returns the filesystem Unix socket path for fd passing.
// macOS does not support abstract Unix sockets.
func tunFdSocketPath() string {
	return fmt.Sprintf("/tmp/easyss-tun-fd-%d.sock", os.Getpid())
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
	defer os.Remove(namePath) //nolint:errcheck

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
	defer os.Remove(namePath) //nolint:errcheck

	_, _ = util.Command("sh", namePath, device, tunGW, localGateway, tunGWV6, serverIPV6, localGatewayV6)
	return nil
}
