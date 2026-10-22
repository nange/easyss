//go:build (darwin || linux) && !headless

package tunhelper

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
// 但它整个生命周期持有 lockPath 的排他 flock，而内核在进程退出（含 kill -9）时释放它。
func waitTunHelperExit(lockPath string, timeout time.Duration) error {
	lock, err := os.OpenFile(lockPath, os.O_RDONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // 还没有 helper 创建过这把锁
	}
	if err != nil {
		return fmt.Errorf("open %s: %w", lockPath, err)
	}
	defer lock.Close() //nolint:errcheck

	deadline := time.Now().Add(timeout)
	for {
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			// 只为探测锁是否已释放，立刻还回去，否则会挡住紧接着启动的下一个 helper。
			return util.Unflock(lock)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("tun helper still holds %s after %v", lockPath, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// defaultOps 返回生产实现：控制锁、路由探测与提权回滚。
func defaultOps() ops {
	return ops{
		lockPath: tunControlLockPath,
		probe: func(device, tunGW string) (string, bool) {
			return probeTunRouteResidue(util.Command, device, tunGW)
		},
		rollback: func(dev tun.DeviceConfig) error {
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
		},
	}
}

// 等 helper 释放控制锁后自己复核一遍路由表。等不到 helper 也往下走：复核会自己发现残留。
func (o ops) teardown(dev tun.DeviceConfig, owner tun.Owner, helperSignalled bool) error {
	// 只有 helper 装的会话才有"等它退出"这一步；直连路径没有 helper。
	if owner == tun.OwnerHelper && helperSignalled {
		if err := waitTunHelperExit(o.lockPath, tunHelperExitTimeout); err != nil {
			log.Error("[SYSTRAY] tunDown: waiting for tun helper", "err", err)
		}
	}
	return o.verify(dev)
}

// 返回非 nil 表示路由仍然残留且回滚也没清掉，由调用方告知用户。
func (o ops) verify(dev tun.DeviceConfig) error {
	detail, leftover := o.probe(dev.Device, dev.TunGW)
	if !leftover {
		return nil
	}

	log.Error("[SYSTRAY] TUN routes survived teardown, rolling back",
		"device", dev.Device, "tun_gw", dev.TunGW, "detail", detail)

	if err := o.rollback(dev); err != nil {
		return fmt.Errorf("回滚 TUN 路由失败: %w", err)
	}
	if detail, stillLeft := o.probe(dev.Device, dev.TunGW); stillLeft {
		return fmt.Errorf("回滚后 TUN 路由仍然残留: %s", detail)
	}

	log.Warn("[SYSTRAY] rolled back leftover TUN routes", "device", dev.Device, "tun_gw", dev.TunGW)
	return nil
}

// DefaultVerify 是 session 拆除后的路由/DNS 复核入口。
func DefaultVerify() func(tun.DeviceConfig, tun.Owner, bool) error {
	return defaultOps().teardown
}
