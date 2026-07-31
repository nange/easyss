//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/nange/easyss/v3/scripts"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

// tunFdSocketPath returns the abstract Unix socket path for fd passing.
// Abstract sockets (@-prefixed) do not require a filesystem entry and are
// immune to mount namespace isolation from pkexec.
func tunFdSocketPath() string {
	return fmt.Sprintf("@easyss-tun-fd-%d", os.Getpid())
}

// openTunDevice creates a TUN device on Linux using /dev/net/tun and the
// TUNSETIFF ioctl. It returns the raw file descriptor and the actual
// interface name assigned by the kernel.
func openTunDevice(name string) (int, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var ifr struct {
		name  [unix.IFNAMSIZ]byte
		flags uint16
		_     [22]byte
	}
	copy(ifr.name[:], name)
	ifr.flags = unix.IFF_TUN | unix.IFF_NO_PI

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		unix.Close(fd) //nolint:errcheck
		return -1, "", fmt.Errorf("ioctl(TUNSETIFF): %w", errno)
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd) //nolint:errcheck
		return -1, "", fmt.Errorf("set nonblock: %w", err)
	}

	namelen := len(name)
	if namelen > len(ifr.name) {
		namelen = len(ifr.name)
	}
	for i, b := range ifr.name[:namelen] {
		if b == 0 {
			namelen = i
			break
		}
	}
	actualName := string(ifr.name[:namelen])

	return fd, actualName, nil
}

// runCreateScript writes the embedded create_tun_dev.sh to a temp file
// and executes it with the device configuration.
func runCreateScript(device, tunIP, tunGW, localGateway,
	tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6 string) error {
	if scripts.CreateTunBytes == nil {
		return fmt.Errorf("no create script for linux")
	}

	namePath, err := util.WriteToTemp(scripts.CreateTunFilename, scripts.CreateTunBytes)
	if err != nil {
		return fmt.Errorf("write create script: %w", err)
	}
	defer os.RemoveAll(filepath.Dir(namePath)) //nolint:errcheck

	_, err = util.Command("bash", namePath, device, tunIP, tunGW, localGateway,
		tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6)
	if err != nil {
		return fmt.Errorf("exec create script: %w", err)
	}
	return nil
}

// runCloseScript writes the embedded close_tun_dev.sh to a temp file
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

	_, _ = util.Command("bash", namePath, device, tunGW, localGateway, tunGWV6, serverIPV6, localGatewayV6)
	return nil
}
