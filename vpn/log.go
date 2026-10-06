package vpn

import (
	"fmt"

	"tailscale.com/types/logger"

	"github.com/nange/easyss/v3/log"
)

// Logf 把 tailscale 与 tailcat 的 printf 风格日志接到 easyss 的 slog 上。
//
// 放在 debug 级别：这些日志主要是连接级事件（接入、断开、转发失败），频率与在线
// 节点数同阶，默认级别下不该与代理自己的日志抢注意力。
//
// 它被 vpn（DERP 中继）与 vpn/node（tailcat 节点栈）共用，因此是导出的：两边的
// 第三方库都要求 logger.Logf 形态的回调。
func Logf(format string, args ...any) {
	log.Debug("[VPN] " + fmt.Sprintf(format, args...))
}

// 编译期断言：Logf 满足 tailscale 的 logger.Logf 形态，避免签名漂移后在调用点
// 才报错。tailcat.Server.Logf / tailcat.Client.Logf 用的是同一个类型。
var _ logger.Logf = Logf
