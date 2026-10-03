//go:build !darwin && !linux && !headless

package main

import (
	"time"

	"github.com/nange/easyss/v3/client/tun"
)

// waitTunHelperExit 在非 darwin/linux 平台上是空操作：这些平台没有提权 TUN
// helper，TUN 设备与路由由 client/tun 自己通过创建/关闭脚本管理。
func waitTunHelperExit(time.Duration) error { return nil }

// verifyTunTeardown 在非 darwin/linux 平台上是空操作：Windows 的 TUN 路由挂在
// 适配器上、由关闭脚本随适配器一起清理，没有可按网关探测的残留；这些平台也没有
// 提权 helper 会话，因此不需要 tunRouteResidue/rollbackTunRoutes 那套探测与回滚
// （它们在 darwin/linux 上由 tray_tun_teardown_unix.go 定义）。
func verifyTunTeardown(tun.DeviceConfig) error { return nil }
