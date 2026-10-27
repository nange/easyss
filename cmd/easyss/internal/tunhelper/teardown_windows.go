//go:build windows && !headless

package tunhelper

import (
	"fmt"

	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
)

func defaultOps() ops {
	return ops{probe: func(tunGW string) (string, bool) {
		out, err := util.Command("route", "print", "-4")
		if err != nil {
			log.Warn("[SYSTRAY] probe tun routes", "err", err)
			return "", false
		}
		return parseRoutePrintResidue(out, tunGW)
	}}
}

// teardown 只复核不删除：关闭脚本已经由提权 helper 执行，父进程没有权限再回滚。
func (o ops) teardown(dev tun.DeviceConfig, _ tun.Owner, _ bool) error {
	if o.probe == nil || dev.TunGW == "" {
		return nil
	}

	detail, leftover := o.probe(dev.TunGW)
	if !leftover {
		return nil
	}
	return fmt.Errorf("TUN 路由仍残留: %s", detail)
}

// DefaultVerify 是 session 拆除后的路由复核入口；Windows 上没有可用的提权回滚路径。
func DefaultVerify() func(tun.DeviceConfig, tun.Owner, bool) error {
	return defaultOps().teardown
}
