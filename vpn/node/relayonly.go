package vpnnode

import (
	"strconv"

	"tailscale.com/envknob"
)

// RelayOnlyEnvKnob 是 tailscale 用来强制"只走 DERP 中继、禁用节点间直连"的调试
// 开关名（`wgengine/magicsock/debugknobs.go` 的 debugAlwaysDERP）。
//
// 它被导出有两个原因：日志要把这个名字打给用户（这是 `TS_DEBUG_` 前缀的调试开关，
// 未来 tailscale 版本可能改名，出问题时用户需要知道去哪查），测试也要按它断言。
const RelayOnlyEnvKnob = "TS_DEBUG_ALWAYS_USE_DERP"

// ApplyRelayOnly 打开/关闭"强制全部经 DERP 中继"。
//
// 三条使用约束，都来自这个开关的实现方式（`envknob.Setenv` 直接写注册过的全局
// 变量，见附录 A.2）：
//
//   - **进程级**：tailscale 没有 per-connection 粒度，因此无法"只对某个对端强制
//     中继"，只能整进程一起。调用点因此固定在 VPN 栈的构造处，而不是每个对端各设
//     一次。
//   - **必须在任何 tailcat Client/Server 启动之前**：magicsock 在建 socket 时读
//     这个开关，之后再改不会回头重建已经绑好的 UDP socket。
//   - **显式写 true 与 false**：同一个进程可能先后跑多次会话（Android 的启停、
//     托盘的切换），上一次留下的 true 会让下一次的 relay_only=false 静默失效。
//
// 生效后的直接后果是 magicsock 绑 `newBlockForeverConn()`——**完全不创建 UDP
// socket**，唯一出口是到 DERP 主机的 TCP 连接（见 docs/vpn-design.md 8.1）。
func ApplyRelayOnly(on bool) {
	envknob.Setenv(RelayOnlyEnvKnob, strconv.FormatBool(on))
}
