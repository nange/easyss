//go:build darwin

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/scripts"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

const utunControlName = "com.apple.net.utun_control"

// tunFdSocketPath 返回用于 fd 传递的文件系统 Unix socket 路径。
// macOS 不支持抽象 Unix socket。
func tunFdSocketPath() string {
	return fmt.Sprintf("/tmp/easyss-tun-fd-%d.sock", os.Getpid())
}

// openTunDevice 在 macOS 上使用 SYSPROTO_CONTROL 内核控制 socket
// 机制创建 TUN 设备。它返回原始文件描述符以及内核分配的实际接口名。
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

// runCreateScript 将内嵌的 create_tun_dev_darwin.sh 写入临时文件，
// 并使用设备配置执行它。
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

	// create_tun_dev_darwin.sh 会自己给地址拼上 "/64"（ifconfig 的 inet6
	// 参数必须带前缀长度），而 TunIPV6Sub 是按 linux 脚本的
	// "ip -6 addr replace" 以 CIDR 形式携带前缀的，因此先剥掉前缀再交给
	// 脚本：否则会拼出 ".../64/64"，ifconfig 报 "bad value" 并以退出码 1
	// 结束，整个 TUN 启动随之失败。
	if err := execScriptWithOutput("sh", namePath, device, tunIP, tunGW, localGateway,
		bareV6Addr(tunIPV6Sub), tunGWV6, serverIPV6, localGatewayV6); err != nil {
		return err
	}
	return nil
}

// bareV6Addr 去掉 IPv6 地址上的前缀长度（"2001:db8::1/64" -> "2001:db8::1"），
// 因为 create_tun_dev_darwin.sh 会自己补上 "/64"。
func bareV6Addr(sub string) string {
	addr, _, _ := strings.Cut(sub, "/")
	return addr
}

// runCloseScript 将内嵌的 close_tun_dev_darwin.sh 写入临时文件并执行。
// 错误会被忽略，因为这是尽力而为的清理。
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

// removeLeftoverDevice 报告在关闭脚本执行后仍然存在的 TUN 接口。
// 路由本身由关闭脚本按前缀删除，utun 接口会随持有它的最后一个 fd
// 一起消失，所以这里没有需要强制清理的东西：该检查只是让残留的接口
// 变得可见。
func removeLeftoverDevice(device string) {
	if _, err := util.Command("ifconfig", device); err == nil {
		log.Warn("[TUN-HELPER] tun device survived cleanup", "device", device)
	}
}

// ensureTunRoutes 校验 TUN 接口仍处于 up 状态且 TUN 路由仍然存在，
// 当 macOS 清掉了它们（睡眠/唤醒或网络变化）时重新运行创建脚本。
// 重新应用已有配置产生的错误会被容忍：ifconfig 和 route 只会报
// "File exists"。
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
	return runCreateScript(device, cfg.TunIP, cfg.TunGW, cfg.LocalGateway,
		cfg.TunIPV6Sub, cfg.TunGWV6, cfg.ServerIPV6, cfg.LocalGatewayV6)
}
