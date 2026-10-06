package vpnnode

import (
	"net/netip"
	"strings"
)

// ResolveStatic 把对端名字解析成它的 overlay IPv4。它同时满足两个 DNS 前端的
// 静态名接口（client/dns.StaticNames 与 client/proxy.VPNStaticNames，两者方法集
// 相同）：TUN 模式下的查询到达代理的 DNS 拦截器，而 enable_forward_dns 的 LAN
// 部署走转发服务器——两处都必须命中（见 docs/vpn-design.md 5.4）。
//
// 非 TUN 模式下应用书写的对端名由系统解析器处理，那时应用应当显式使用代理
// SOCKS5 端口。
//
// 返回 false 表示"不是配置的对端名"，调用方必须原样转发：钩子只在命中时改变
// 行为。名字的比较不区分大小写（DNS 名字本身如此），并去掉末尾的根点。
func (r *Route) ResolveStatic(name string) (netip.Addr, bool) {
	if r == nil || r.overlay == nil {
		return netip.Addr{}, false
	}
	return r.overlay.Addr(trimDNSRoot(name))
}

// trimDNSRoot 去掉 DNS 问题名末尾的根点。
//
// 问题名（dns.Question.Name）总是以 "." 结尾，而配置里的 host_name 是人类书写
// 的形式（"b"），因此比较前必须归一化。只去一个点：host_name 里若真的含点
// （"b.lan"），它仍然能匹配对应的 FQDN（"b.lan."）。
func trimDNSRoot(name string) string {
	return strings.TrimSuffix(name, ".")
}
