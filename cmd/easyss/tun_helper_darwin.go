//go:build darwin

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/scripts"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

const utunControlName = "com.apple.net.utun_control"

// macOS 不支持抽象 Unix socket。
func tunFdSocketPath() string {
	return fmt.Sprintf("/tmp/easyss-tun-fd-%d.sock", os.Getpid())
}

// 用 SYSPROTO_CONTROL 内核控制 socket 创建设备，返回原始 fd 与内核分配的实际接口名。
// 设备 MTU 由创建脚本的第 9 个实参设置，这里只负责把设备建出来。
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

// fd 路径下设备 MTU 只能由创建脚本第 9 个位置参数写入，否则 netstack 静默丢弃超限包；
// 位置参数由 tun.ScriptArgs 渲染，darwin 的第 5 位必须是裸 IPv6 地址。
func runCreateScript(device string, args tun.ScriptArgs) error {
	if scripts.CreateTunBytes == nil {
		return fmt.Errorf("no create script for darwin")
	}

	namePath, err := tun.WriteScriptToTemp(scripts.CreateTunFilename, scripts.CreateTunBytes)
	if err != nil {
		return fmt.Errorf("write create script: %w", err)
	}
	defer os.Remove(namePath) //nolint:errcheck

	// 以调用方传入的为准：helper 拿到的是内核实际分配的名字，配置里那个只是请求名。
	args.Dev.Device = device
	if err := execScriptWithOutput("sh", namePath, args.Create()...); err != nil {
		return err
	}
	return nil
}

// 脚本按"路由是否真的删掉"给出退出码，调用方据此决定是否回滚：
// 残留的分流默认路由会把全机 IPv4 流量送进没人读的设备，也就是"停止 TUN 后断网"。
func runCloseScript(device string, args tun.ScriptArgs) error {
	if scripts.CloseTunBytes == nil {
		return fmt.Errorf("no close script for darwin")
	}

	namePath, err := tun.WriteScriptToTemp(scripts.CloseTunFilename, scripts.CloseTunBytes)
	if err != nil {
		return fmt.Errorf("write close script: %w", err)
	}
	defer os.Remove(namePath) //nolint:errcheck

	args.Dev.Device = device
	if err := execScriptWithOutput("sh", namePath, args.Close()...); err != nil {
		return fmt.Errorf("close script: %w", err)
	}
	return nil
}

// 主判据是网关：TUN 路由按 `route add -net X <tun_gw>` 安装，而设备名可能重名或与内核实际名不符，
// 按它判定会误判别人的路由；无网关信息时才退回设备名。
func probeTunRouteResidue(run func(string, ...string) (string, error), device, tunGW string) (string, bool) {
	key, value := "gateway:", tunGW
	if value == "" {
		key, value = "interface:", device
	}
	if value == "" {
		return "", false
	}

	var out string
	for _, target := range tunRouteProbes {
		got, err := run("route", "-n", "get", target)
		if err != nil {
			continue
		}
		out = got
		if routeFieldsContain(got, key, value) {
			return got, true
		}
	}
	return out, false
}

// 路由由关闭脚本按前缀删除，utun 接口随最后一个 fd 消失，因此这里只让残留接口变得可见。
func removeLeftoverDevice(device string) {
	if _, err := util.Command("ifconfig", device); err == nil {
		log.Warn("[TUN-HELPER] tun device survived cleanup", "device", device)
	}
}

// 接口不在 up 或其 IP 丢失（macOS 在睡眠/唤醒或网络变化后所为）时重跑创建脚本；"File exists" 错误会被容忍。
func ensureTunRoutes(device string, cfg *proxy.TunConfig) error {
	needCreate := false

	out, err := util.Command("ifconfig", device)
	if err != nil || !strings.Contains(out, "UP") || !strings.Contains(out, cfg.TunIP) {
		log.Warn("[TUN-HELPER] interface check failed", "device", device, "err", err)
		needCreate = true
	}

	if !needCreate {
		routeOut, err := probeRoutedViaDevice(tunRouteProbes, func(probe string) (string, error) {
			return util.Command("route", "-n", "get", probe)
		}, "interface: "+device)
		if err != nil {
			log.Warn("[TUN-HELPER] route check failed", "device", device, "probe", tunRouteProbes, "err", err, "output", routeOut)
			needCreate = true
		}
	}

	if !needCreate {
		return nil
	}

	log.Info("[TUN-HELPER] recreating TUN routes", "device", device)
	return runCreateScript(device, scriptArgsFor(cfg))
}
