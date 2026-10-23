package dns

import (
	"net/netip"

	"github.com/miekg/dns"

	"github.com/nange/easyss/v3/stats"
)

// StaticNames 是本地静态名的来源，命中时由 DNS 前端就地应答、不再向上游查询。
// 接口定义在消费方：实现方 vpn/node 已依赖 client/proxy，反向依赖会形成导入环。
type StaticNames interface {
	// ResolveStatic 报告 name 是否是需要本地应答的名字，并返回其 IPv4 地址；name
	// 末尾带根点（"b."）。返回 false 时调用方必须原样转发。
	ResolveStatic(name string) (netip.Addr, bool)
}

// StaticNameTTL 是静态名应答的 TTL（秒）。overlay 地址按对端公钥在同一段内线性
// 探测分配，增删 peer 可能让其他对端换地址，TTL 越短旧地址仍指向另一个对端的窗口越短。
const StaticNameTTL = 60

// StaticReply 为一条查询构造本地静态应答，返回 false 表示交给原路径。两个 DNS 前端
// （client/proxy 拦截器与 client/dns 转发服务器）共用它：A 查询返回 overlay IPv4，
// AAAA 查询返回 NOERROR 且无记录（NXDOMAIN 会被读成名字不存在）。
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
