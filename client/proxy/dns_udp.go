package proxy

import (
	"context"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
)

// udpReply 把一条 DNS 应答交回客户端：msg 供同步分支（屏蔽/缓存/直连）使用，
// raw 供异步的代理分支使用——后者的应答由 udpPool.receiveLoop 在任意时刻送回。
// 两者的组帧都由前端负责（SOCKS5 数据报必须按客户端请求的目标地址封装）。
type udpReply struct {
	msg func(*dns.Msg) error
	raw func([]byte)
}

// udpDNSQuery 是一条已完成解包的 UDP DNS 查询及其应答通道。
// raw 是原始数据报载荷，用于经隧道发出（首载荷会合并进引导记录）。
type udpDNSQuery struct {
	raw   []byte
	msg   *dns.Msg
	dst   string
	reply udpReply
}

// handleUDPQuery 处理一条 UDP DNS 查询：Block 本地屏蔽，缓存命中直接应答，
// Direct 走直连解析，其余经隧道到 config.ProxyDNSServer。
func (d *dnsInterceptor) handleUDPQuery(clientAddr *net.UDPAddr, req udpDNSQuery) error {
	plan := d.plan(req.msg)
	switch plan.action {
	case dnsActionBlock:
		log.Info("[DNS_BLOCK] blocked", "domain", plan.domain, "qtype", plan.qtype)
		return req.reply.msg(blockedDNSReply(req.msg))
	case dnsActionCacheHit:
		return req.reply.msg(plan.cached)
	case dnsActionDirect:
		return d.directUDPQuery(req, plan)
	default:
		return d.proxyUDPQuery(clientAddr, req, plan)
	}
}

// directUDPQuery 同步解析一条直连查询并立即应答：客户端显式请求的解析器
// （req.dst）优先，失败回落到内置/系统 DNS。
func (d *dnsInterceptor) directUDPQuery(req udpDNSQuery, plan dnsPlan) error {
	log.Info("[DNS_DIRECT]", "domain", plan.domain, "qtype", plan.qtype)
	stats.RecordDNSDirectQuery()

	resp, err := d.resolveDirectDNS(req.msg, plan.domain, req.dst)
	if err != nil {
		log.Error("[DNS_DIRECT]", "domain", plan.domain, "err", err)
		return err
	}
	log.Info("[DNS_DIRECT] result", "domain", plan.domain, "qtype", plan.qtype, "answers", util.DNSAnswerStrings(resp))

	resp.Id = req.msg.Id
	return req.reply.msg(resp)
}

// proxyUDPQuery 把一条查询交给经隧道的 UDP 交换。首载荷合并进引导记录时不需要
// 额外发送；后续查询直接复用现有交换。应答由 receiveLoop 异步送回。
func (d *dnsInterceptor) proxyUDPQuery(clientAddr *net.UDPAddr, req udpDNSQuery, plan dnsPlan) error {
	// upstream 是本代理解析查询的位置；客户端请求的是其自身解析器所配置的
	// 服务器，而应答必须伪装成来自该地址（req.dst），与其他所有 DNS 分支
	// 一致。如果改用 upstream 来封装应答，透明 NAT（tun2socks）会把它丢弃：
	// 流是按客户端的目标来标识的，声称来自不同服务器的数据报永远不会匹配，
	// 查询就会看起来没有得到应答。
	upstream := config.ProxyDNSServer
	key := clientAddr.String() + "_" + upstream

	log.Info("[DNS_PROXY]", "domain", plan.domain, "qtype", plan.qtype)
	stats.RecordDNSProxyQuery()

	ue, created, err := d.pool.acquireExchange(context.Background(), key, upstream, req.raw)
	if err != nil {
		log.Error("[UDP_PROXY] open exchange", "dst", upstream, "err", err)
		return err
	}
	onData := func(data []byte) {
		if req.reply.raw != nil {
			req.reply.raw(d.postProcessProxied(data))
		}
	}
	if created {
		go d.pool.receiveLoop(ue, key, d.respTimeout, onData)
		return nil // 第一个载荷已在握手中发送
	}

	if err := ue.Send(req.raw); err != nil {
		log.Error("[UDP_PROXY] send", "err", err)
		d.pool.removeExchange(key, ue)
		return err
	}
	return nil
}

// postProcessProxied 处理一条经隧道返回的 DNS 应答：按 ipv6 策略剥离 AAAA、
// 写入代理缓存、记录结果并按自定义域名规则学习。解包失败或不是响应时原样返回。
func (d *dnsInterceptor) postProcessProxied(data []byte) []byte {
	msg := &dns.Msg{}
	if err := msg.Unpack(data); err != nil || !util.IsDNSResponse(msg) {
		return data
	}
	if d.router.ShouldIPV6Disable() && msg.Question[0].Qtype == dns.TypeAAAA {
		msg.Answer = nil
		if packed, packErr := msg.Pack(); packErr == nil {
			data = packed
		}
	}
	_ = d.cache.Set(msg, false)

	domain := strings.TrimSuffix(msg.Question[0].Name, ".")
	qtype := dns.TypeToString[msg.Question[0].Qtype]
	log.Info("[DNS_PROXY] result", "domain", domain, "qtype", qtype, "answers", util.DNSAnswerStrings(msg))

	d.learnDNSAnswers(msg, domain, false)
	return data
}
