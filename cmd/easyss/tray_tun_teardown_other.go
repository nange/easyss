//go:build (!darwin && !linux) || headless

package main

import "github.com/nange/easyss/v3/client/tun"

// finishTunTeardown 在非 darwin/linux 平台与 headless 构建上是空操作：前者没有
// 提权 helper（TUN 路由挂在适配器上，由关闭脚本随适配器一起清理，没有可按网关
// 探测的残留），后者没有运行期的 TUN 开关路径（TUN 只可能在启动时由 App.Start
// 直接创建，拆除由 session.stop 收走 manager 完成）。
//
// 因此这些平台上没有"等 helper 退出"与"复核路由表"两步，也就不需要它们的存根：
// waitTunHelperExit 与 verifyTunTeardown 只由 darwin/linux 的实现（见
// tray_tun_teardown_unix.go）提供，那个实现与这里互斥编译。
func (s *session) finishTunTeardown(*tun.DeviceConfig, bool) {}
