package dns

import (
	"net/netip"

	"github.com/miekg/dns"

	"github.com/nange/easyss/v3/stats"
)

// StaticNames 是本地静态名的来源：命中时由 DNS 前端就地应答，不再向上游查询
// （见 docs/vpn-design.md 5.4）。
//
// 接口定义在消费方（本包）：实现方是 vpn/node 的 Route，而 vpn/node 已经依赖
// client/proxy，反向依赖会造成导入环。
type StaticNames interface {
	// ResolveStatic 报告 name 是否是需要本地应答的名字，并给出它的 IPv4 地址。
	//
	// name 是 DNS 问题名，末尾带根点（"b."）。返回 false 时调用方必须原样转发：
	// 钩子不得改变任何非本地名的既有行为。
	ResolveStatic(name string) (netip.Addr, bool)
}

// StaticNameTTL 是静态名应答的 TTL（秒）。
//
// 取得较短是有意的：overlay 地址由对端公钥在同一段内线性探测分配，对端集合一
// 变（增删一个 peer）就可能让别的对端换地址，因此解析器缓存过期得越快，"改了
// peers 之后旧地址还指向另一个对端"的窗口就越短。
const StaticNameTTL = 60

// StaticReply 为一条查询构造本地静态应答。返回 false 表示"交给原路径"：不是
// 静态名、没有静态名来源，或查询类型与"名字 → 地址"无关。
//
// 它被**两个 DNS 前端共用**，这是硬要求而不是复用癖：客户端在 TUN 模式下的查询
// 经 tun2socks 到达代理的 DNS 拦截器（`client/proxy`），而 `enable_forward_dns`
// 部署（LAN 设备把 DNS 指向本机）走 client/dns 的转发服务器。两条路径各写一份
// A/AAAA 语义必然漂移，而这里的两条契约都不允许漂移（见 docs/vpn-design.md 5.4）：
//
//   - A 查询返回该名字的 overlay IPv4；
//   - AAAA 查询返回 NOERROR 且**无记录**——不是 NXDOMAIN。overlay 段只有 IPv4，
//     空应答让客户端立刻回退到 A 记录，而 NXDOMAIN 会被读成"这个名字不存在"。
func StaticReply(static StaticNames, req *dns.Msg) (*dns.Msg, bool) {
	if static == nil || req == nil || len(req.Question) == 0 {
		return nil, false
	}
	q := req.Question[0]
	addr, ok := static.ResolveStatic(q.Name)
	if !ok {
		return nil, false
	}

	reply := new(dns.Msg)
	reply.SetReply(req)
	switch q.Qtype {
	case dns.TypeA:
		if !addr.Is4() {
			// overlay 段必然是 IPv4（配置校验保证），这里只是不让一个坏实现
			// 在 A 记录里塞进 IPv6 地址。
			return nil, false
		}
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    StaticNameTTL,
			},
			A: addr.AsSlice(),
		})
	case dns.TypeAAAA:
		// 刻意留空：NOERROR 且无记录。
	default:
		return nil, false
	}
	stats.RecordVPNDNSStaticAnswer()
	return reply, true
}
