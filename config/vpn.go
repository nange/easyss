package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// VPN 组网（内嵌 DERP 的节点互访）的共享常量与归一化入口。
//
// 设计见 docs/vpn-design.md。这里只放"客户端与服务端都必须一致"的那部分，
// 各自 JSON 视图的默认值仍由 client/config 与 server/config 的 applyDefaults
// 负责，避免出现第二份定义。

const (
	// DefaultVPNPeerPort 是节点对端面（被访问方）在 tailcat 隧道内监听的端口。
	// 它**不在宿主上监听**，只存在于 tailcat 的 gVisor netstack 里，因此与宿主
	// 已占用的端口不会冲突，也不需要任何端口预留。
	//
	// vpn.peer_port 未配置时按既有惯例从 socks_port 派生（+vpnPeerPortOffset），
	// 派生结果越界时回退到这里。
	DefaultVPNPeerPort = 6080

	// vpnPeerPortOffset 是 vpn.peer_port 相对 socks_port 的派生偏移，沿用
	// http_port = socks_port + 1000 的既有惯例（client/config/build.go）。
	// 取 2000 而不是 1000，是为了在 http_port 已被 +1000 占用的前提下留出一段
	// 间隔，使同一个 socks_port 派生出的一组默认端口彼此不重叠。
	vpnPeerPortOffset = 2000

	// vpnMaxPort 是 TCP/UDP 端口的合法上界，用于判断派生结果是否越界。
	vpnMaxPort = 65535

	// DefaultVPNOverlayCIDR 是访问侧在**本地**给对端分配的 overlay 虚拟 IPv4
	// 段。它只用于访问侧本地的两件事：TUN 模式下静态解析对端名字的 DNS 应答，
	// 以及 SOCKS5 路由判定。它**不进隧道**、对端永远看不到，因此不需要与其他
	// 节点保持一致（见 docs/vpn-design.md 5.1）。
	//
	// 选 198.19.0.0/24（RFC 2544 benchmarking 段）而非 100.64.0.0/10（CGNAT）：
	// 后者在物理接口上常常已经存在一条 on-link 路由，它比 TUN 安装的
	// 128.0.0.0/1 阶梯更具体，会把 overlay 流量压回物理网卡；198.19.0.0/24
	// 公网不路由，不会与任何真实链路冲突。
	DefaultVPNOverlayCIDR = "198.19.0.0/24"

	// DefaultVPNDERPPath 是内嵌 DERP 服务在 easyss 服务端 HTTPS 监听上的挂载
	// 路径。DERP 客户端用 HTTP/1.1 Upgrade 连到 https://<host>:<port><path>。
	DefaultVPNDERPPath = "/derp"

	// DefaultVPNRegionID 是内嵌 DERP 在自产 DERPMap 里使用的 region 编号。
	//
	// 它必须非零（tailcat.Server.Start 拒绝 RegionID 为 0 的 region），并且
	// 应当远离 Tailscale 官方 region 的编号区间，以免两个来源的 DERPMap 在日志
	// 或排障输出里互相混淆。官方编号目前是 1..~30 与 900 附近，这里取 901。
	DefaultVPNRegionID = 901

	// vpnMaxOverlayPrefixBits 是 overlay 段允许的最长前缀（最小的段）：overlay
	// 地址是按对端公钥在其中逐个分配的，/31 与 /32 放不下"若干个对端"，因此
	// 把它们当作配置错误而不是可用的段。
	vpnMaxOverlayPrefixBits = 30

	// vpnMinOverlayPrefixBits 是 overlay 段允许的最短前缀（最大的段）。
	//
	// 这个下界不是审美问题：槽位分配按段容量开一张表（见 vpn/node/overlay.go
	// 的 Assign），容量是 2^(32-bits)。没有下界时，一份"看起来合法"的
	// overlay_cidr（例如 0.0.0.0/0 或 10.0.0.0/8）会让启动直接申请 4 GiB /
	// 16 MiB 并清零，32 位平台上还会因 int 溢出 panic。/16 对应 65534 个槽位
	// （64 KiB），足以容纳任何现实规模的对端列表。
	vpnMinOverlayPrefixBits = 16
)

// NormalizeVPNPeerPort 是 vpn.peer_port 的唯一归一化入口。
//
// 语义与 NormalizeTimeout / NormalizeTunMTU 一致：0（含负值）表示"未配置"，
// 此时从 socks_port 派生；派生的前提是 socks_port 本身合法且加上偏移后仍在
// 端口范围内，否则（以及派生值越界时）回退 DefaultVPNPeerPort。
//
// 之所以只在无法派生时回退，而不是把越界的 socks_port 也拿来派生：socks_port
// 为 0 在完整模式里是合法配置（表示不启动本地 SOCKS5 代理），此时并不存在一个
// 可用的"邻近端口"语义。
func NormalizeVPNPeerPort(peerPort, socksPort int) int {
	if peerPort <= 0 && socksPort > 0 && socksPort <= vpnMaxPort-vpnPeerPortOffset {
		peerPort = socksPort + vpnPeerPortOffset
	}
	if peerPort <= 0 || peerPort > vpnMaxPort {
		return DefaultVPNPeerPort
	}
	return peerPort
}

// ParseVPNOverlayCIDR 解析并归一化 vpn.overlay_cidr，是它的唯一校验入口：
// 空值取 DefaultVPNOverlayCIDR；其余值必须是合法的 IPv4 前缀、前缀长度落在
// [vpnMinOverlayPrefixBits, vpnMaxOverlayPrefixBits] 内，并归一化为网络地址
// （198.19.0.5/24 → 198.19.0.0/24）。
//
// 只接受 IPv4：overlay 地址是给 TUN 模式下的 A 记录应答用的，而本设计的
// overlay 段刻意只覆盖 IPv4（AAAA 查询一律回 NOERROR 空应答，见
// docs/vpn-design.md 5.4）。
func ParseVPNOverlayCIDR(s string) (netip.Prefix, error) {
	if s == "" {
		return netip.MustParsePrefix(DefaultVPNOverlayCIDR), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid overlay CIDR %q: %w", s, err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("invalid overlay CIDR %q: only IPv4 is supported", s)
	}
	if p.Bits() > vpnMaxOverlayPrefixBits || p.Bits() < vpnMinOverlayPrefixBits {
		return netip.Prefix{}, fmt.Errorf("invalid overlay CIDR %q: prefix length must be between /%d and /%d",
			s, vpnMinOverlayPrefixBits, vpnMaxOverlayPrefixBits)
	}
	return p.Masked(), nil
}

// DefaultVPNOverlayPrefix 返回 DefaultVPNOverlayCIDR 的解析结果。默认值是常量，
// 因此解析不可能失败；这里 panic 只是为了让"常量被改坏"在测试中就暴露出来。
func DefaultVPNOverlayPrefix() netip.Prefix {
	p, err := ParseVPNOverlayCIDR(DefaultVPNOverlayCIDR)
	if err != nil {
		panic(fmt.Sprintf("config.DefaultVPNOverlayCIDR %q is not a valid prefix: %v", DefaultVPNOverlayCIDR, err))
	}
	return p
}

// DERPAddr 是一个已校验的 DERP 对外地址（host 与数字端口）。
//
// 拆成结构体而不是两个返回值，因为本包是 Android AAR 的绑定面（Makefile 的
// easyss-android-aar 绑定 ./mobile/ ./config/），而 gobind 要求导出函数最多
// 返回一个值（外加 error）。同理，这里的字段刻意都是 gobind 支持的基本类型。
type DERPAddr struct {
	Host string
	Port int
}

// SplitDERPAddr 把 "host:port" 形式的 DERP 地址拆成主机名与端口号，是
// server.vpn.derp_addr 与 vpn.derp_addr 的共同校验入口。
//
// 两端共用它是有必要的：这个值最终会变成 DERPMap 里节点的 HostName 与 DERPPort
// （一个 int），所以端口必须显式且是数字，host 必须非空。服务名（":https"）虽然
// 对 net.Listen 合法，但在这里必须拒绝——对端把它读成 DERPPort 时没有地方去解析
// 服务名。
func SplitDERPAddr(addr string) (DERPAddr, error) {
	if addr == "" {
		return DERPAddr{}, fmt.Errorf("DERP address is empty")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return DERPAddr{}, fmt.Errorf("invalid DERP address %q: %w", addr, err)
	}
	if host == "" {
		return DERPAddr{}, fmt.Errorf("invalid DERP address %q: host is empty", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return DERPAddr{}, fmt.Errorf("invalid DERP address %q: port %q is not in 1..65535", addr, portStr)
	}
	return DERPAddr{Host: host, Port: port}, nil
}

// PortFromListen 从监听地址（如 ":443"、"0.0.0.0:8443"、"[::]:https"）解析出
// 数值端口。服务名交给 net.LookupPort 解析（对已知服务名是纯本地查表）。
func PortFromListen(listen string) (int, error) {
	_, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, fmt.Errorf("invalid listen address %q: %w", listen, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q in listen address %q: %w", portStr, listen, err)
	}
	return port, nil
}
