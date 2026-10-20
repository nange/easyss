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

// easyssTunSubnet 是 easyss TUN 设备所在的子网。
var easyssTunSubnet = net.IPNet{
	IP:   net.IPv4(198, 18, 0, 0),
	Mask: net.CIDRMask(15, 32),
}

// IsTunSubnetAddr 报告 ip 是否位于 easyss TUN 子网（默认 198.18.0.0/15）。
func IsTunSubnetAddr(ip net.IP) bool {
	return easyssTunSubnet.Contains(ip)
}

// IsTunIface 识别 easyss TUN 设备：名称匹配两个平台的默认设备名（与当前平台无关），
// 或持有 TUN 子网内的地址。直连拨号器绝不能绑定它，否则出站包会被送回 TUN 形成路由环路。
func IsTunIface(iface *net.Interface) bool {
	if iface == nil {
		return false
	}
	if iface.Name == sharedconfig.DefaultTunDeviceName ||
		iface.Name == sharedconfig.DefaultTunDeviceNameDarwin {
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

// SysDefaultRoute 只有 Windows 走这里：其路由查找会拒绝 0.0.0.0/8 目标，无法像 darwin/linux
// 那样探测 0.0.0.1（easyss TUN 路由都从 1.0.0.0/8 开始，探测地址必定落在物理接口上）。
func SysDefaultRoute() (iface *net.Interface, gateway net.IP, err error) {
	switch runtime.GOOS {
	case "windows":
		return defaultRouteFromWinTable()
	default:
		return nil, nil, errUnsupportedPlatform
	}
}

// Android 上应用既访问不了 netlink 路由 socket，也没有 SO_BINDTODEVICE 所需的 CAP_NET_RAW；
// 而 VpnService 按应用路由，本应用自己的 socket 无需绑定就能绕过隧道。
func SysDirectIfaceBindUnsupported() bool {
	return runtime.GOOS == "android"
}

func SysGatewayAndDevice() (gw string, dev string, err error) {
	iface, gateway, err := SysDefaultRoute()
	if err == nil && iface != nil && gateway != nil {
		return gateway.String(), iface.Name, nil
	}

	// 兜底（darwin、linux 等）：探测 0.0.0.1，该地址不会被从 1.0.0.0/8
	// 开始的 easyss TUN 路由覆盖。
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
