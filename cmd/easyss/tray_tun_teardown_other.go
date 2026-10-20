//go:build (!darwin && !linux) || headless

package main

import "github.com/nange/easyss/v3/client/tun"

// 非 darwin/linux 平台与 headless 构建没有运行期的 TUN 拆除路径：前者没有提权 helper
// （路由挂在适配器上随适配器一起清理），后者没有 TUN 开关。
func defaultTunOps() tunOps { return tunOps{} }

func (tunOps) teardown(tun.DeviceConfig, tun.Owner, bool) error { return nil }
