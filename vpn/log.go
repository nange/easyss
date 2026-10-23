package vpn

import (
	"fmt"

	"tailscale.com/types/logger"

	"github.com/nange/easyss/v3/log"
)

// Logf 把 tailscale/tailcat 的 printf 日志接到 easyss 的 slog，固定 debug 级别：这些是
// 连接级事件，频率与在线节点数同阶。vpn 与 vpn/node 两边的第三方库都要求 logger.Logf
// 形态，因此必须导出。
func Logf(format string, args ...any) {
	log.Debug("[VPN] " + fmt.Sprintf(format, args...))
}

// 编译期断言：Logf 满足 tailscale 的 logger.Logf（tailcat 的 Logf 字段同型）。
var _ logger.Logf = Logf
