package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// VPN 组网（内嵌 DERP 的节点互访）的共享常量与归一化入口：客户端与服务端必须
// 使用同一份定义，各自的 JSON 默认值仍由 client/config、server/config 的
// applyDefaults 填入。

const (
	// DefaultVPNPeerPort 是节点对端面（被访问方）在 tailcat 隧道内监听的端口，
	// 不在宿主上监听（只存在于 gVisor netstack），因此无需端口预留；
	// vpn.peer_port 未配置时从 socks_port 派生，派生越界时回退到这里。
	DefaultVPNPeerPort = 6080

	// vpnPeerPortOffset 是 vpn.peer_port 相对 socks_port 的派生偏移；必须大于
	// DefaultHTTPPortOffset，否则同一 socks_port 派生的 peer_port 与 http_port 会重叠。
	vpnPeerPortOffset = 2000

	// vpnMaxPort 是 TCP/UDP 端口的合法上界，用于判断派生结果是否越界。
	vpnMaxPort = 65535

	// DefaultVPNOverlayCIDR 是访问侧本地给对端分配的唯一的 overlay IPv4 段：只用于
	// 本机静态解析与 SOCKS5 路由判定，不进隧道、对端不可见，无需与其他节点一致。
	// 勿换成 100.64.0.0/10：物理网卡常已有更具体的 on-link 路由，会截走 overlay 流量。
	DefaultVPNOverlayCIDR = "198.19.0.0/24"

	// DefaultVPNDERPPath 是内嵌 DERP 服务在 easyss 服务端 HTTPS 监听上的挂载
	// 路径。DERP 客户端用 HTTP/1.1 Upgrade 连到 https://<host>:<port><path>。
	DefaultVPNDERPPath = "/derp"

	// DefaultVPNRegionID 是内嵌 DERP 在自产 DERPMap 里使用的 region 编号，必须非零
	// （tailcat.Server.Start 拒绝 RegionID 为 0）；取值避开 Tailscale 官方区间，以免
	// 两个来源的 DERPMap 在日志里互相混淆。
	DefaultVPNRegionID = 901

	// MaxVPNRelays 是同一 region 内嵌 DERP 中继总数上限，客户端与服务端共用：mesh 必须
	// 全互联，且每个节点地址内嵌的中继集合必须与所有对端相等，超限配置没有可工作的
	// 形态，因此两侧都在配置加载阶段拒绝启动。
	MaxVPNRelays = 3

	// DefaultDERPSendQueueDepth 是内嵌 DERP 为每个已连接客户端缓存待发帧数的默认值
	// （server.vpn.derp_send_queue_depth 的 0 值落点）：中继路径上只有这里能存住未确认
	// 数据，吞吐 ≈ 深度 × 1.4KB / RTT。实测见 docs/architecture.md 要点 19。
	DefaultDERPSendQueueDepth = 1024

	// MinDERPSendQueueDepth 是队列深度的下界：配得更小只会让中继路径比默认更差。
	MinDERPSendQueueDepth = 16

	// MaxDERPSendQueueDepth 是队列深度的上界（4096 帧 ≈ 6MB/客户端），防止把字节数
	// 误配成帧数。
	MaxDERPSendQueueDepth = 4096

	// vpnMaxOverlayPrefixBits 是 overlay 段允许的最长前缀（最小的段）：overlay
	// 地址是按对端公钥在其中逐个分配的，/31 与 /32 放不下"若干个对端"，因此
	// 它们不是可用的段。
	vpnMaxOverlayPrefixBits = 30

	// vpnMinOverlayPrefixBits 是 overlay 段允许的最短前缀：槽位表按 2^(32-bits) 预分配
	// （见 vpn/node/overlay.go 的 Assign），没有下界时一个 0.0.0.0/0 会在启动时申请
	// 4 GiB，32 位平台还会因 int 溢出 panic。
	vpnMinOverlayPrefixBits = 16
)

// NormalizeVPNPeerPort 是 vpn.peer_port 的唯一归一化入口：<=0 表示未配置，从合法的
// socks_port 加偏移派生；socks_port 为 0 在完整模式下合法（不启动本地 SOCKS5），
// 此时以及派生越界都回退 DefaultVPNPeerPort。
func NormalizeVPNPeerPort(peerPort, socksPort int) int {
	if peerPort <= 0 && socksPort > 0 && socksPort <= vpnMaxPort-vpnPeerPortOffset {
		peerPort = socksPort + vpnPeerPortOffset
	}
	if peerPort <= 0 || peerPort > vpnMaxPort {
		return DefaultVPNPeerPort
	}
	return peerPort
}

// NormalizeDERPSendQueueDepth 是 server.vpn.derp_send_queue_depth 的唯一归一化入口：
// 0 取默认、越界取最近边界；必须在消费点（vpn.NewDERPServer）调用，不能写回配置字段，
// 否则"未配置"与"显式配成默认值"无法区分。
func NormalizeDERPSendQueueDepth(depth int) int {
	switch {
	case depth <= 0:
		return DefaultDERPSendQueueDepth
	case depth < MinDERPSendQueueDepth:
		return MinDERPSendQueueDepth
	case depth > MaxDERPSendQueueDepth:
		return MaxDERPSendQueueDepth
	}
	return depth
}

// parseVPNOverlayCIDR 解析并归一化 overlay 段：只接受 IPv4，前缀长度必须落在
// [vpnMinOverlayPrefixBits, vpnMaxOverlayPrefixBits] 内并掩成网络地址。
// 没有配置项，入参只可能是 DefaultVPNOverlayCIDR；改坏它会在启动时暴露。
func parseVPNOverlayCIDR(s string) (netip.Prefix, error) {
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

// DefaultVPNOverlayPrefix 返回 DefaultVPNOverlayCIDR 的解析结果，是运行期拿到
// overlay 段的**唯一**入口。默认值是常量，因此解析不可能失败；这里 panic 只是为了
// 让"常量被改坏"在启动时就暴露出来（启动路径不返回配置错误——它不是配置）。
func DefaultVPNOverlayPrefix() netip.Prefix {
	p, err := parseVPNOverlayCIDR(DefaultVPNOverlayCIDR)
	if err != nil {
		panic(fmt.Sprintf("config.DefaultVPNOverlayCIDR %q is not a valid prefix: %v", DefaultVPNOverlayCIDR, err))
	}
	return p
}

// DERPAddr 是一个已校验的 DERP 对外地址。本包是 Android AAR 的 gobind 绑定面，
// 导出函数最多返回一个值，字段也只能用 gobind 支持的基本类型。
type DERPAddr struct {
	Host string
	Port int
}

// SplitDERPAddr 把 "host:port" 拆成 host 与数字端口，是服务端对外地址与节点
// servers[] 的共同校验入口：该端口会写进 DERPMap 的 DERPPort（int），服务名
// （如 ":https"）虽然对 net.Listen 合法，也必须拒绝。
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

// CanonicalDERPAddr 把 DERP host:port 规范化成可比较形态（主机名小写、十进制端口、
// IPv6 带方括号）。相等判定必须经过它，否则同一中继的两种书写会被当成两个。
func CanonicalDERPAddr(addr string) (string, error) {
	da, err := SplitDERPAddr(addr)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(strings.ToLower(da.Host), strconv.Itoa(da.Port)), nil
}

// ParseVPNMeshKey 把 server.vpn.mesh_key 归一化为 64 位 hex：已是 64 位 hex 则转小写
// 原样使用，其余非空字符串取 SHA-256。空值报错；两侧密钥不一致不会报错，mesh 只是
// 静默建不起来。
func ParseVPNMeshKey(s string) (string, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "", errors.New("mesh key is empty")
	}
	if len(trimmed) == 64 {
		if _, err := hex.DecodeString(trimmed); err == nil {
			return strings.ToLower(trimmed), nil
		}
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:]), nil
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
