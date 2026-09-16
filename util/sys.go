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

// easyssTunSubnet 是 easyss TUN 设备默认拥有的子网
// （TunIP/TunGW 默认为 198.18.0.1，掩码 255.255.0.0）。
var easyssTunSubnet = net.IPNet{
	IP:   net.IPv4(198, 18, 0, 0),
	Mask: net.CIDRMask(15, 32),
}

// IsTunSubnetAddr 报告 ip 是否位于 easyss TUN 子网内
// （默认为 198.18.0.0/15，即 TUN 设备自身地址所在的网段）。
func IsTunSubnetAddr(ip net.IP) bool {
	return easyssTunSubnet.Contains(ip)
}

// IsTunIface 报告 iface 是否为 easyss TUN 设备：其名称匹配
// easyss TUN 设备名（windows/linux 上为 tun-easyss，darwin 上为 utun9 —
// 两者都会被匹配，因此识别不依赖当前平台），
// 或它拥有 easyss TUN 子网内的地址。直连拨号器绝不能绑定到该接口 —
// 绑定它会把每个出站数据包送回 TUN 设备，从而通过
// tun2socks 形成路由环路。
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

// SysDefaultRoute 返回 IPv4 默认路由（0.0.0.0/0）的物理接口和网关，
// 数据来自 Windows 路由表。TUN 激活时 Windows 可能持有多个 0.0.0.0/0
// 条目（netsh 配置静态网关时 TUN 设备会获得自己的默认路由）；
// 会跳过 easyss TUN 接口，从而返回物理接口。在 darwin 和 linux 上，
// 调用方改为探测 0.0.0.1 — easyss TUN 路由在所有平台上都从 1.0.0.0/8
// 开始，因此 0.0.0.1 始终解析到物理默认接口（Windows 无法使用该探测：
// 其路由查找会直接拒绝 0.0.0.0/8 目标）。
func SysDefaultRoute() (iface *net.Interface, gateway net.IP, err error) {
	switch runtime.GOOS {
	case "windows":
		return defaultRouteFromWinTable()
	default:
		return nil, nil, errUnsupportedPlatform
	}
}

// SysDirectIfaceBindUnsupported 报告平台是否无法将直连拨号器绑定到
// 物理接口。在 Android 上，应用无法访问 netlink 路由 socket
// （net.Interfaces、net.Interface.Addrs 和 go-netroute 的路由探测都会
// 因权限被拒绝而失败），而 SO_BINDTODEVICE 需要应用不具备的
// CAP_NET_RAW。那里的 VpnService 型 VPN 使用按应用路由
// （只有被选中的应用进入 TUN），因此应用自身的 socket —
// 包括到远程服务器的传输连接 — 无需任何绑定即可绕过隧道。
// 因此在 Android 上直连拨号器保持不绑定。
func SysDirectIfaceBindUnsupported() bool {
	return runtime.GOOS == "android"
}

func SysGatewayAndDevice() (gw string, dev string, err error) {
	iface, gateway, err := SysDefaultRoute()
	if err == nil && iface != nil && gateway != nil {
		return gateway.String(), iface.Name, nil
	}

	// 兜底方案（darwin、linux 及其他平台）：探测 0.0.0.1，该地址
	// 不会被 easyss TUN 路由（在所有平台上都从 1.0.0.0/8 开始）覆盖。
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
