package vpnnode

import (
	"net/netip"
	"strings"
)

// ResolveStatic 把对端名字解析成它的 overlay IPv4，同时满足 client/dns.StaticNames
// 与 client/proxy.VPNStaticNames 两个前端（TUN 拦截器与转发服务器都必须命中）。
// 返回 false 表示不是配置的对端名，调用方必须原样转发；比较忽略大小写与末尾根点。
func (r *Route) ResolveStatic(name string) (netip.Addr, bool) {
	if r == nil || r.overlay == nil {
		return netip.Addr{}, false
	}
	return r.overlay.Addr(trimDNSRoot(name))
}

// trimDNSRoot 去掉 DNS 问题名末尾的根点：问题名总是以 "." 结尾，而配置里的
// host_name 是人类书写形式。只去一个点，"b.lan" 仍能匹配 "b.lan."。
func trimDNSRoot(name string) string {
	return strings.TrimSuffix(name, ".")
}
