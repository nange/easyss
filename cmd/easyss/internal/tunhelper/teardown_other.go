//go:build (!darwin && !linux && !windows) || headless

package tunhelper

import "github.com/nange/easyss/v3/client/tun"

// 既没有 unix 提权流程也不是 Windows 的平台、以及所有 headless 构建，都没有运行期的
// TUN 拆除路径：前者没有提权 helper（路由挂在适配器上随适配器一起清理），后者没有 TUN 开关。
func defaultOps() ops { return ops{} }

func (ops) teardown(tun.DeviceConfig, tun.Owner, bool) error { return nil }

// DefaultVerify 在无提权 helper 的平台上无事可做。
func DefaultVerify() func(tun.DeviceConfig, tun.Owner, bool) error {
	return defaultOps().teardown
}
