package util

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

func IsIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsLANIP 判断 ip 是否落在代理服务器绝不应拨号的非公网范围：除私有/环回/链路本地/
// 多播/未指定外，还包括 CGNAT、基准测试与文档网段、240.0.0.0/4；IPv4 映射形式经 To4 覆盖。
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
			(ip4[0] == 192 && ip4[1] == 0) || // 192.0.0.0/16，含协议分配与文档网段
			(ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)) || // 198.18.0.0/15 benchmarking
			(ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100) || // 198.51.100.0/24 TEST-NET-2
			(ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113) || // 203.0.113.0/24 TEST-NET-3
			ip4[0] >= 224 // 224.0.0.0/4 起：多播、保留段与广播地址
	}

	return _ip.IsPrivate() || _ip.IsLoopback() || _ip.IsLinkLocalMulticast() ||
		_ip.IsLinkLocalUnicast() || _ip.IsUnspecified() || _ip.IsMulticast() ||
		_ip.IsInterfaceLocalMulticast()
}

// 调用方必须校验全部返回地址并只拨这些字面地址：SSRF 检查与实际连接共用同一次解析，
// DNS-rebinding 没有翻转答案的窗口；字面 IP 直接返回，ctx 无截止时间时套 3s 兜底。
func ResolveHostIPs(ctx context.Context, addr string) ([]netip.Addr, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return nil, errors.New("empty host")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}

	resolveCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		resolveCtx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}

	ips, err := net.DefaultResolver.LookupNetIP(resolveCtx, "ip", host)
	if err != nil {
		return nil, err
	}
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.Unmap())
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	return addrs, nil
}

// 返回 addrs 中第一个 LAN/保留地址，全为公网时返回零值；判断前必须剥掉 zone
// （fe80::1%eth0），否则 net.ParseIP 解析失败、链路本地目标会被漏判。
func FirstLANAddr(addrs []netip.Addr) netip.Addr {
	for _, addr := range addrs {
		if IsLANIP(addr.WithZone("").String()) {
			return addr
		}
	}
	return netip.Addr{}
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
