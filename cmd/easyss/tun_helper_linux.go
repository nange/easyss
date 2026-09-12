//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/log"
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

	namelen := min(len(name), len(ifr.name))
	for i, b := range ifr.name[:namelen] {
		if b == 0 {
			namelen = i
			break
		}
	}
	actualName := string(ifr.name[:namelen])

	// The interface may already exist as a *persistent* TUN device: older
	// easyss versions created it with "ip tuntap add mode tun" from the create
	// script, and TUNSETIFF above happily re-attaches to such a device without
	// touching the flag. A persistent device outlives the fds that hold it, so
	// a failed delete at shutdown (see removeLeftoverDevice) leaves the
	// interface and every TUN route in the routing table forever. Clearing the
	// flag makes the device disappear with the last fd again, which is what
	// the fd-passing helper design expects.
	if err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 0); err != nil {
		log.Warn("[TUN-HELPER] clear tun persist flag", "device", actualName, "err", err)
	}

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
	defer os.Remove(namePath) //nolint:errcheck

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
	defer os.Remove(namePath) //nolint:errcheck

	_, _ = util.Command("bash", namePath, device, tunGW, localGateway, tunGWV6, serverIPV6, localGatewayV6)
	return nil
}

// removeLeftoverDevice deletes the TUN interface when it survived the close
// script. Deleting the interface is what takes the TUN routes with it, and the
// close script's own "ip tuntap del" cannot do that while a process still
// holds the device open: iproute2 attaches through TUNSETIFF, and the kernel
// refuses a second attach to a device that is already attached ("device or
// resource busy"). The client closes its fd concurrently with the close
// script, so that delete used to fail and leave the interface plus every split
// route in the routing table: all traffic then entered a device nothing reads
// from, which looks like "the network is down" after stopping TUN. "ip link
// del" tears the interface down regardless of open fds.
func removeLeftoverDevice(device string) {
	if _, err := util.Command("ip", "link", "show", device); err != nil {
		return // the close script already deleted it
	}

	log.Warn("[TUN-HELPER] tun device survived cleanup, deleting it", "device", device)
	if _, err := util.Command("ip", "link", "del", device); err != nil {
		log.Error("[TUN-HELPER] delete tun device failed", "device", device, "err", err)
	}
}

// ensureTunRoutes verifies the TUN interface is still up and the TUN routes
// are still present, re-running the create script when they were cleared
// (e.g. by NetworkManager after a connection change or sleep/wake). Errors
// from re-applying existing configuration are tolerated: ip only reports
// "File exists".
func ensureTunRoutes(device string, cfg *proxy.TunConfig) error {
	needCreate := false

	out, err := util.Command("ip", "link", "show", device)
	if err != nil || !strings.Contains(out, "UP") {
		log.Warn("[TUN-HELPER] interface check failed", "device", device, "err", err)
		needCreate = true
	}

	if !needCreate {
		routeOut, err := probeRoutedViaDevice(tunRouteProbes, func(probe string) (string, error) {
			return util.Command("ip", "route", "get", probe)
		}, "dev "+device)
		if err != nil {
			log.Warn("[TUN-HELPER] route check failed", "device", device, "probe", tunRouteProbes, "err", err, "output", routeOut)
			needCreate = true
		}
	}

	if !needCreate {
		return nil
	}

	log.Info("[TUN-HELPER] recreating TUN routes", "device", device)
	return runCreateScript(device, cfg.TunIP, cfg.TunGW, cfg.LocalGateway,
		cfg.TunIPV6Sub, cfg.TunGWV6, cfg.ServerIPV6, cfg.LocalGatewayV6)
}
