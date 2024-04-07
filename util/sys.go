package util

import (
	"net"
	"os/exec"
	"strconv"

	netroute "github.com/libp2p/go-netroute"
)

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

func SysGatewayAndDevice() (gw string, dev string, err error) {
	r, _ := netroute.New()
	iface, gateway, _, err := r.Route(net.IPv4(119, 29, 29, 29))
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
