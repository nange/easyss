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

// waitTunHelperExit 等待提权 helper 释放 TUN 控制锁，也就是等它完成清理并退出。
//
// helper 由 osascript/pkexec 以后台方式拉起（PPID 为 1），父进程既拿不到它的 pid
// 也无法 Wait；但它在整个生命周期里持有 tunControlLockPath 的排他 flock，而内核
// 会在进程退出时释放它（被 kill -9 也一样）。因此"能否立刻取得这把锁"就是
// "helper 是否已经退出"的可靠信号。
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
			// 只是为了探测"锁是否已释放"：立刻还回去，否则会挡住紧接着要启动的
			// 下一个 helper。
			return util.Unflock(lock)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("tun helper still holds %s after %v", tunControlLockPath, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// finishTunTeardown 是 session.tunDown 的第 3 步在 darwin/linux 上的实现：
// 等提权 helper 释放控制锁（即它已完成路由/DNS 清理并退出），然后自己复核一遍
// 系统路由表。
//
// 拆除过去是彻底"发射后不管"的：父进程既不等也不看，于是助手进程一旦清路由失败，
// 1/8…128/1 这些分流默认路由就留在表里，把全机 IPv4 流量（包括 DNS）送进一个已经
// 没人读的设备——表现为"切换服务器后本机断网"。等不到 helper 也往下走：下面的
// 复核会自己发现残留。Windows 与 headless 构建走上游的 no-op 版本。
func (s *session) finishTunTeardown(dev *tun.DeviceConfig, helperSignalled bool) {
	if helperSignalled {
		if err := waitTunHelperExit(tunHelperExitTimeout); err != nil {
			log.Error("[SYSTRAY] tunDown: waiting for tun helper", "err", err)
		}
	}
	if dev == nil {
		return
	}
	if err := verifyTunTeardown(*dev); err != nil {
		log.Error("[SYSTRAY] tunDown: TUN teardown left routes behind", "err", err)
		s.app.notifyTunTeardownProblem(
			"TUN 已停止，但系统路由表里仍残留指向 TUN 的路由，本机可能无法上网。请退出并重新启动 Easyss，或重启系统以恢复网络。详情：" + err.Error())
	}
}

// rollbackTunRoutes 重新执行平台的关闭脚本（必要时由脚本路径再次提权）。
// 它是变量以便测试注入：真实实现会提权并改写运行测试的机器的路由表。
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

// verifyTunTeardown 核对一次 TUN 会话留下的系统改动是否真的撤销了，返回非 nil
// 表示"路由仍然残留，且回滚也没能清掉"，由调用方负责告知用户。
//
// 拆除是 helper 异步完成的，父进程过去既不等也不查：只要有一条分流默认路由
// （1/8…128/1）残留，全机 IPv4 流量就会进入一个没人读的设备——用户看到的就是
// "切换服务器后本机断网"。这里在 helper 退出后自己复核一遍，必要时提权回滚。
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
