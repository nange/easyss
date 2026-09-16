package util

import (
	"context"
	"net"
	"time"
)

func IsIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsLANIP 报告 ip 是否为 LAN/私有/环回/链路本地/多播/未指定地址，
// 或是否落在代理服务器绝不应拨号的任何其他非公网范围内：
// 运营商级 NAT（100.64.0.0/10）、"本网络" 范围（0.0.0.0/8）、
// IETF 协议分配与文档网段（192.0.0.0/16，含 192.0.0.0/24 协议分配段
// 及 192.0.1.0/24–192.0.3.0/24 文档网段）、基准测试网段（198.18.0.0/15）、
// 文档网段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24）、
// 保留的 240.0.0.0/4 和广播地址。
// IPv4 检查为内联实现，因此 IPv4 映射的 IPv6 形式（::ffff:a.b.c.d）
// 通过 To4 一并覆盖。
func IsLANIP(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}

	if ip4 := _ip.To4(); ip4 != nil {
		return ip4[0] == 0 || // 0.0.0.0/8
			ip4[0] == 10 || // 10.0.0.0/8
			(ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127) || // 100.64.0.0/10 CGNAT
			ip4[0] == 127 || // 127.0.0.0/8
			(ip4[0] == 169 && ip4[1] == 254) || // 169.254.0.0/16 link-local
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) || // 172.16.0.0/12
			(ip4[0] == 192 && ip4[1] == 168) || // 192.168.0.0/16
			(ip4[0] == 192 && ip4[1] == 0) || // 192.0.0.0/16，含协议分配段 192.0.0.0/24 与文档网段 192.0.1.0/24–192.0.3.0/24
			(ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)) || // 198.18.0.0/15 benchmarking
			(ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100) || // 198.51.100.0/24 TEST-NET-2
			(ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113) || // 203.0.113.0/24 TEST-NET-3
			ip4[0] >= 224 // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, 255.255.255.255 broadcast
	}

	return _ip.IsPrivate() || _ip.IsLoopback() || _ip.IsLinkLocalMulticast() ||
		_ip.IsLinkLocalUnicast() || _ip.IsUnspecified() || _ip.IsMulticast() ||
		_ip.IsInterfaceLocalMulticast()
}

func IsLoopbackIP(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}

	return _ip.IsLoopback()
}

// IsLANHost 检查主机地址（带或不带端口）是否为 LAN/私有地址。
// 它用于通过拒绝指向内部网络的目标来防止 SSRF 攻击。
//
// 注意：这是一个快速的纯 IP 检查。这里不会解析域名，因此解析到 LAN 地址的
// 域名会返回 false。如需防止基于域名的绕过，请改用 IsLANHostResolved。
func IsLANHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return IsLANIP(host)
}

// IsLANHostResolved 是 IsLANHost 的 SSRF 安全版本：当主机是域名
// 而非字面 IP 时，它会解析该域名，并在任一解析结果地址为 LAN/私有地址时
// 拒绝请求。当主机本身已是字面 IP 时走快速的纯 IP 路径，
// 因此常见情况不会产生 DNS 查询。
//
// 传入的 ctx 用于约束 DNS 解析，以免挂起的解析器拖住握手。
func IsLANHostResolved(ctx context.Context, addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if IsLANIP(host) {
		return true
	}
	// 非 LAN 的字面 IP：安全。
	if IsIP(host) {
		return false
	}
	if host == "" {
		return false
	}

	// 域名：解析并检查每个结果地址。当调用方的 ctx 没有截止时间时，
	// 会应用一个较短的兜底超时，这样缓慢的 DNS 服务器就无法无限期
	// 拖住握手。
	resolveCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		resolveCtx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}

	ips, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		// 解析失败时放行（返回 false），让拨号层产生真实的错误。
		// SSRF 防护依赖后续检查的通过；无法解析的域名反正也到不了局域网主机。
		return false
	}
	for _, ip := range ips {
		if IsLANIP(ip.IP.String()) {
			return true
		}
	}
	return false
}

func IsIPV6(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}

	if _ip.To4() != nil {
		return false
	} else if _ip.To16() != nil {
		return true
	}

	return false
}

func IsIPV6Addr(addr string) bool {
	host, _, _ := net.SplitHostPort(addr)
	return IsIPV6(host)
}
