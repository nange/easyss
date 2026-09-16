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

// tunFdSocketPath 返回用于传递文件描述符的抽象 Unix 套接字路径。
// 抽象套接字（以 @ 开头）不需要文件系统条目，也不会受到 pkexec 的挂载命名空间
// 隔离影响。
func tunFdSocketPath() string {
	return fmt.Sprintf("@easyss-tun-fd-%d", os.Getpid())
}

// openTunDevice 使用 /dev/net/tun 和 TUNSETIFF ioctl 在 Linux 上创建 TUN 设备。
// 它返回原始文件描述符以及内核实际分配的接口名。
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

	// 该接口可能已经以*持久化* TUN 设备的形式存在：旧版 easyss 由 create 脚本通过
	// "ip tuntap add mode tun" 创建它，上面的 TUNSETIFF 会重新挂接到这种设备，
	// 而不会触及持久化标志。持久化设备比持有它的 fd 存活得更久，因此关闭时删除
	// 失败（参见 removeLeftoverDevice）会让接口及其全部 TUN 路由永远留在路由表中。
	// 清除该标志后，设备会随最后一个 fd 一起消失，这正是 fd 传递型辅助进程设计
	// 所期望的行为。
	if err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 0); err != nil {
		log.Warn("[TUN-HELPER] clear tun persist flag", "device", actualName, "err", err)
	}

	return fd, actualName, nil
}

// runCreateScript 将内嵌的 create_tun_dev.sh 写入临时文件，
// 并使用设备配置执行它。
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

	if err := execScriptWithOutput("bash", namePath, device, tunIP, tunGW, localGateway,
		tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6); err != nil {
		return err
	}
	return nil
}

// runCloseScript 将内嵌的 close_tun_dev.sh 写入临时文件并执行它。
// 由于这是尽力而为的清理操作，错误会被忽略。
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

// removeLeftoverDevice 在 TUN 接口未被 close 脚本删除时将其删除。删除接口会
// 一并带走其上的 TUN 路由；而只要有进程仍持有设备打开，close 脚本自身的
// "ip tuntap del" 就做不到这一点：iproute2 通过 TUNSETIFF 挂接设备，内核会拒绝
// 再次挂接一个已挂接的设备（报 "device or resource busy"）。客户端与 close 脚本
// 并发地关闭其 fd，因此那次删除曾经失败，接口及其全部分流路由都留在路由表中：
// 所有流量随后进入一个无人读取的设备，停止 TUN 后便表现为"网络已断开"。
// "ip link del" 无论 fd 是否仍处于打开状态都会拆除接口。
func removeLeftoverDevice(device string) {
	if _, err := util.Command("ip", "link", "show", device); err != nil {
		return // the close script already deleted it
	}

	log.Warn("[TUN-HELPER] tun device survived cleanup, deleting it", "device", device)
	if _, err := util.Command("ip", "link", "del", device); err != nil {
		log.Error("[TUN-HELPER] delete tun device failed", "device", device, "err", err)
	}
}

// ensureTunRoutes 校验 TUN 接口仍处于 up 状态且 TUN 路由仍然存在，当它们被清除时
// （例如 NetworkManager 在连接变更或睡眠/唤醒后所为）重新运行 create 脚本。
// 重复应用已有配置所产生的错误会被容忍：ip 只会报出 "File exists"。
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
