//go:build darwin || linux

package main

import "github.com/nange/easyss/v3/client/tun"

// tunOps 是一次 TUN 会话的平台操作：控制锁路径、路由残留探测与提权回滚。
// 生产实现由 defaultTunOps 提供，测试构造自己的实例即可注入。
type tunOps struct {
	lockPath string
	probe    func(device, tunGW string) (string, bool)
	rollback func(tun.DeviceConfig) error
}
