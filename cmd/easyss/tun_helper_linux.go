//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/scripts"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

// 抽象套接字（@ 开头）不需要文件系统条目，也不受 pkexec 的挂载命名空间隔离影响。
func tunFdSocketPath() string {
	return fmt.Sprintf("@easyss-tun-fd-%d", os.Getpid())
}

// 设备 MTU 由创建脚本的第 9 个实参设置，这里只负责把设备建出来。
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

	// TUNSETIFF 会重新挂接已存在的持久化 TUN 设备而不碰持久化标志，而持久化设备比持有它的 fd 活得更久：
	// 关闭时删除失败（见 removeLeftoverDevice）会让接口及其全部 TUN 路由永远留在路由表里。
	// 清掉该标志后设备随最后一个 fd 消失，这才是 fd 传递型 helper 想要的行为。
	if err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 0); err != nil {
		log.Warn("[TUN-HELPER] clear tun persist flag", "device", actualName, "err", err)
	}

	return fd, actualName, nil
}

// fd 路径下 tun2socks 只能设自己 netstack 的 MTU，设备 MTU 必须由建设备的这一侧写入（第 9 个位置参数），
// 否则 netstack 会静默丢弃设备交上来的超限包（见 client/tun.Manager.engineMTU）。
// 位置参数由 tun.ScriptArgs 统一渲染，包括 linux 要求的"地址/掩码"形式。
func runCreateScript(device string, args tun.ScriptArgs) error {
	if scripts.CreateTunBytes == nil {
		return fmt.Errorf("no create script for linux")
	}

	namePath, err := tun.WriteScriptToTemp(scripts.CreateTunFilename, scripts.CreateTunBytes)
	if err != nil {
		return fmt.Errorf("write create script: %w", err)
	}
	defer os.Remove(namePath) //nolint:errcheck

	// 以调用方传入的为准：helper 拿到的是内核实际分配的名字，配置里那个只是请求名。
	args.Dev.Device = device
	if err := execScriptWithOutput("bash", namePath, args.Create()...); err != nil {
		return err
	}
	return nil
}

// 脚本按"路由与设备是否真的清掉"给出退出码，调用方据此决定是否回滚：
// 残留的分流路由会把全机 IPv4 流量送进没人读的设备，也就是"停止 TUN 后断网"。
func runCloseScript(device string, args tun.ScriptArgs) error {
	if scripts.CloseTunBytes == nil {
		return fmt.Errorf("no close script for linux")
	}

	namePath, err := tun.WriteScriptToTemp(scripts.CloseTunFilename, scripts.CloseTunBytes)
	if err != nil {
		return fmt.Errorf("write close script: %w", err)
	}
	defer os.Remove(namePath) //nolint:errcheck

	args.Dev.Device = device
	if err := execScriptWithOutput("bash", namePath, args.Close()...); err != nil {
		return fmt.Errorf("close script: %w", err)
	}
	return nil
}

// linux 的 TUN 路由按设备安装（ip route replace ... dev tun0），因此按设备名判定。
func probeTunRouteResidue(run func(string, ...string) (string, error), device, _ string) (string, bool) {
	if device == "" {
		return "", false
	}

	var out string
	for _, target := range tunRouteProbes {
		got, err := run("ip", "route", "get", target)
		if err != nil {
			continue
		}
		out = got
		if routeFieldsContain(got, "dev", device) {
			return got, true
		}
	}
	return out, false
}

// 只要有进程仍持有设备打开，close 脚本的 "ip tuntap del" 就会被内核拒绝（"device or resource busy"），
// 接口及其分流路由于是留在路由表里，所有流量进入无人读取的设备；`ip link del` 不受 fd 打开状态影响。
func removeLeftoverDevice(device string) {
	if _, err := util.Command("ip", "link", "show", device); err != nil {
		return // the close script already deleted it
	}

	log.Warn("[TUN-HELPER] tun device survived cleanup, deleting it", "device", device)
	if _, err := util.Command("ip", "link", "del", device); err != nil {
		log.Error("[TUN-HELPER] delete tun device failed", "device", device, "err", err)
	}
}

// 接口不在 up 或路由已被清掉（NetworkManager 在连接变更、睡眠/唤醒后所为）时重跑 create 脚本；
// "File exists" 之类的重复应用错误会被容忍。重跑同时把设备 MTU 写回配置值，这是它的自愈点。
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
	return runCreateScript(device, scriptArgsFor(cfg))
}
