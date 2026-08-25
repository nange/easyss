package util

import (
	"errors"
	"net"
	"os/exec"
	"runtime"
	"strconv"

	netroute "github.com/libp2p/go-netroute"

	sharedconfig "github.com/nange/easyss/v3/config"
)

// easyssTunSubnet is the subnet that the easyss TUN device owns by default
// (TunIP/TunGW default to 198.18.0.1 with mask 255.255.0.0).
var easyssTunSubnet = net.IPNet{
	IP:   net.IPv4(198, 18, 0, 0),
	Mask: net.CIDRMask(15, 32),
}

// defaultTunDeviceName returns the default easyss TUN device name for the
// current platform, mirroring the defaults in client/tun.New.
func defaultTunDeviceName() string {
	if runtime.GOOS == "darwin" {
		return sharedconfig.DefaultTunDeviceNameDarwin
	}
	return sharedconfig.DefaultTunDeviceName
}

// IsTunSubnetAddr reports whether ip lies in the easyss TUN subnet
// (198.18.0.0/15 by default, where the TUN device's own address lives).
func IsTunSubnetAddr(ip net.IP) bool {
	return easyssTunSubnet.Contains(ip)
}

// IsTunIface reports whether iface is the easyss TUN device: its name matches
// the easyss TUN device name, or it owns an address in the easyss TUN subnet.
// The direct dialer must never bind to this interface — binding to it would
// send every outbound packet back into the TUN device, creating a routing
// loop through tun2socks.
func IsTunIface(iface *net.Interface) bool {
	if iface == nil {
		return false
	}
	if iface.Name == defaultTunDeviceName() {
		return true
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && IsTunSubnetAddr(ipnet.IP) {
			return true
		}
	}
	return false
}

func SysSupportPowershell() bool {
	return SysSupport("powershell")
}

func SysSupportXTerminalEmulator() bool {
	return SysSupport("x-terminal-emulator")
}

func SysSupportGnomeTerminal() bool {
	return SysSupport("gnome-terminal")
}

func SysSupportKonsole() bool {
	return SysSupport("konsole")
}

func SysSupportXfce4Terminal() bool {
	return SysSupport("xfce4-terminal")
}

func SysSupportLxterminal() bool {
	return SysSupport("lxterminal")
}

func SysSupportMateTerminal() bool {
	return SysSupport("mate-terminal")
}

func SysSupportTerminator() bool {
	return SysSupport("terminator")
}

func SysSupport(bin string) bool {
	lp, err := exec.LookPath(bin)
	if lp != "" && err == nil {
		return true
	}
	return false
}

func SysPowershellMajorVersion() int {
	buf, err := Command("powershell", "-Command", "$PSVersionTable.PSVersion")
	if err != nil {
		return 0
	}
	bs := []byte(buf)
	if len(bs) < 64 {
		return 0
	}
	v, _ := strconv.ParseInt(string(bs[64]), 10, 32)
	return int(v)
}

var errUnsupportedPlatform = errors.New("unsupported platform")

// SysDefaultRoute returns the physical interface and gateway of the IPv4
// default route (0.0.0.0/0), read from the Windows routing table. Windows may
// hold several 0.0.0.0/0 entries while TUN is active (the TUN device gets its
// own default route when netsh configures the static gateway); the easyss TUN
// interface is skipped so the physical interface is returned. On darwin and
// linux the caller probes 0.0.0.1 instead — the easyss TUN routes start at
// 1.0.0.0/7 on every platform, so 0.0.0.1 always resolves to the physical
// default interface (Windows cannot use the probe: its route lookup rejects
// 0.0.0.0/8 destinations outright).
func SysDefaultRoute() (iface *net.Interface, gateway net.IP, err error) {
	switch runtime.GOOS {
	case "windows":
		return defaultRouteFromWinTable()
	default:
		return nil, nil, errUnsupportedPlatform
	}
}

func SysGatewayAndDevice() (gw string, dev string, err error) {
	iface, gateway, err := SysDefaultRoute()
	if err == nil && iface != nil && gateway != nil {
		return gateway.String(), iface.Name, nil
	}

	// Fallback (darwin, linux and other platforms): probe 0.0.0.1, which the
	// easyss TUN routes (starting at 1.0.0.0/7 on every platform) never cover.
	r, _ := netroute.New()
	iface, gateway, _, err = r.Route(net.IPv4(0, 0, 0, 1))
	if err != nil {
		return "", "", err
	}

	return gateway.String(), iface.Name, nil
}

func SysGatewayAndDeviceV6() (gw string, dev string, err error) {
	r, _ := netroute.New()
	iface, gateway, _, err := r.Route(net.ParseIP("2400:3200::1"))
	if err != nil {
		return "", "", err
	}

	return gateway.String(), iface.Name, nil
}
