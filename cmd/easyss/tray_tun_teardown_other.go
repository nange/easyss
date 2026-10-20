//go:build (!darwin && !linux) || headless

package main

import "github.com/nange/easyss/v3/client/tun"

// platformTunTeardown 在非 darwin/linux 平台与 headless 构建上是空操作：前者没有提权
// helper（TUN 路由挂在适配器上随适配器一起清理），后者没有运行期的 TUN 开关路径。
func platformTunTeardown(tun.DeviceConfig, tun.Owner, bool) error { return nil }
