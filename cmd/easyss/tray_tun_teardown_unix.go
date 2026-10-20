//go:build (darwin || linux) && !headless

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

// 正常路径上 helper 收到 FIFO 的 EOF 后几十毫秒内退出；超时说明它卡在清理里，
// 继续等只会拖住整个切换流程，此时由父进程自己复核路由表。
const tunHelperExitTimeout = 5 * time.Second

// helper 由 osascript/pkexec 以后台方式拉起（PPID 为 1），父进程既拿不到 pid 也无法 Wait；
// 但它整个生命周期持有 tunControlLockPath 的排他 flock，而内核在进程退出（含 kill -9）时释放它。
func waitTunHelperExit(timeout time.Duration) error {
	lock, err := os.OpenFile(tunControlLockPath, os.O_RDONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // 还没有 helper 创建过这把锁
	}
	if err != nil {
		return fmt.Errorf("open %s: %w", tunControlLockPath, err)
	}
	defer lock.Close() //nolint:errcheck

	deadline := time.Now().Add(timeout)
	for {
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			// 只为探测锁是否已释放，立刻还回去，否则会挡住紧接着启动的下一个 helper。
			return util.Unflock(lock)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("tun helper still holds %s after %v", tunControlLockPath, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// 等 helper 释放控制锁后自己复核一遍路由表，返回非 nil 表示路由仍残留且回滚没清掉。
// 只要有一条分流默认路由（1/8…128/1）留下，全机 IPv4 流量就会进入没人读的设备，表现为切换服务器后断网。
// 等不到 helper 也往下走：下面的复核会自己发现残留。
func platformTunTeardown(dev tun.DeviceConfig, owner tun.Owner, helperSignalled bool) error {
	// 只有 helper 装的会话才有"等它退出"这一步；直连路径没有 helper，helperSignalled 恒为 false。
	if owner == tun.OwnerHelper && helperSignalled {
		if err := waitTunHelperExit(tunHelperExitTimeout); err != nil {
			log.Error("[SYSTRAY] tunDown: waiting for tun helper", "err", err)
		}
	}
	return verifyTunTeardown(dev)
}

// 变量以便测试注入：真实实现会提权并改写运行测试的机器的路由表。
var rollbackTunRoutes = func(dev tun.DeviceConfig) error {
	return tun.CleanupTunDevice(tun.Config{
		Device:         dev.Device,
		TunIP:          dev.TunIP,
		TunGW:          dev.TunGW,
		TunMask:        dev.TunMask,
		TunIPV6Sub:     dev.TunIPV6Sub,
		TunGWV6:        dev.TunGWV6,
		ServerIPV6:     dev.ServerIPV6,
		LocalGateway:   dev.LocalGateway,
		LocalGatewayV6: dev.LocalGatewayV6,
	})
}

// 返回非 nil 表示路由仍然残留且回滚也没清掉，由调用方告知用户。
// helper 的拆除是异步的，这里在它退出后自己复核一遍，必要时提权回滚。
func verifyTunTeardown(dev tun.DeviceConfig) error {
	detail, leftover := tunRouteResidue(dev.Device, dev.TunGW)
	if !leftover {
		return nil
	}

	log.Error("[SYSTRAY] TUN routes survived teardown, rolling back",
		"device", dev.Device, "tun_gw", dev.TunGW, "detail", detail)

	if err := rollbackTunRoutes(dev); err != nil {
		return fmt.Errorf("回滚 TUN 路由失败: %w", err)
	}
	if detail, stillLeft := tunRouteResidue(dev.Device, dev.TunGW); stillLeft {
		return fmt.Errorf("回滚后 TUN 路由仍然残留: %s", detail)
	}

	log.Warn("[SYSTRAY] rolled back leftover TUN routes", "device", dev.Device, "tun_gw", dev.TunGW)
	return nil
}
