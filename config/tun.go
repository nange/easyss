package config

// TUN 设备 MTU 的唯一定义处。
//
// 同一个值决定三件事，任何两处不一致都会造成难定位的静默故障，因此它们的
// 合法性与默认值都由这里的常量与 NormalizeTunMTU 统一负责：
//
//  1. 设备的真实 MTU：它决定内核为本机应用通告的 MSS。它统一由各平台的创建
//     脚本写进设备（linux "ip link set ... mtu"、darwin "ifconfig ... mtu"、
//     Windows "netsh ... set subinterface ... mtu="，见 scripts/create_tun_dev*），
//     因为 fd 路径下设备是提权 helper 建的、主进程只拿到 fd，而 tun2socks 只能
//     设置自己 netstack 的 MTU：Windows 的 wintun 适配器它更是完全碰不到
//     （wireguard-go 只把 MTU 存在内存里，见 tun_windows.go 的 forcedMTU）。
//     darwin/linux 的直连路径上 tun2socks 建完设备也会按同一个值设置一次，
//     那次是幂等的。
//  2. tun2socks netstack 的 MTU（见 client/tun.Config.MTU）。它不得小于设备的
//     真实 MTU：netstack 会直接丢弃读到的、超过自身 MTU 的包（UDP、ICMP 与 IP
//     分片），而 TCP 恰好不受影响——netstack 通告的 MSS 由它的 MTU 推导，本机
//     应用因此发不出超过它的段——于是故障只表现为 UDP/ICMP 静默失败。
//  3. 本机应用看到的路径 MTU：MTU 越大，穿越内核 <-> TUN 边界的包越少（每个包
//     至少一次系统调用），高吞吐时 CPU 更低。这也是同类实现（如 mihomo）把
//     TUN MTU 设到 9000 的原因。
const (
	// DefaultTunMTU 是未配置时的 MTU：以太网惯例值，也是 Linux/macOS 新建
	// TUN 设备的默认值，因此默认配置下的行为与不设置该旋钮时完全一致。
	DefaultTunMTU = 1500

	// MinTunMTU 的下界来自 IPv6：链路 MTU 不得小于 1280（RFC 8200），而 TUN
	// 设备同时承载 IPv6（客户端会安装 ::/1 与 8000::/1 默认路由）。
	MinTunMTU = 1280

	// MaxTunMTU 取 9000（jumbo 帧）。除了超过以太网惯例值后收益递减之外，它
	// 还与 netstack 的接收缓冲耦合：gVisor 的接收窗口自动调优下限是 20 x MSS
	// （InitialCwnd = 10，见 tcp.Endpoint.ModerateRecvBuf），9000 对应 MSS 8960，
	// 即约 179KB，仍在 client/tun 交给 netstack 的 256KB 接收缓冲之内。想再调大
	// 必须先提高那个缓冲，否则接收窗口会小于一个段。
	MaxTunMTU = 9000
)

// NormalizeTunMTU 把用户配置的 MTU 归一化为合法值：非正值表示"未配置"，取
// DefaultTunMTU；其余值钳制到 [MinTunMTU, MaxTunMTU]，越界取最近的边界。
//
// 与 NormalizeTimeout 同理，合法性只在这里定义一次：客户端配置、client/tun.New
// 与提权 helper 都调用它，不再各自判断。
func NormalizeTunMTU(mtu int) int {
	if mtu <= 0 {
		return DefaultTunMTU
	}
	return min(max(mtu, MinTunMTU), MaxTunMTU)
}
