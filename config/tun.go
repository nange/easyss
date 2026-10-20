package config

// 设备 MTU 由各平台创建脚本写入。netstack 的 MTU 不得小于设备 MTU，否则超限包被静默丢弃，
// 而 TCP 因 MSS 自通告不受影响，故障只表现为 UDP/ICMP 失败。
const (
	// 以太网惯例值，也是 Linux/macOS 新建 TUN 设备的默认值。
	DefaultTunMTU = 1500

	// 下界来自 IPv6：链路 MTU 不得小于 1280（RFC 8200），而 TUN 同时承载 IPv6。
	MinTunMTU = 1280

	// 9000（jumbo 帧）与 netstack 的接收缓冲耦合：gVisor 接收窗口下限是 20 x MSS，9000 约
	// 179KB，仍在 client/tun 交给它的 256KB 之内；想再调大必须先提高那个缓冲。
	MaxTunMTU = 9000
)

// 非正值取 DefaultTunMTU，其余钳制到 [MinTunMTU, MaxTunMTU]。
func NormalizeTunMTU(mtu int) int {
	if mtu <= 0 {
		return DefaultTunMTU
	}
	return min(max(mtu, MinTunMTU), MaxTunMTU)
}
