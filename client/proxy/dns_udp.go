package proxy

import (
	"context"
	"net"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
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
// src/dst 只用于日志：请求来源与客户端询问的解析器。端口门控之后的 UDP DNS
// 拦截一律以 53 为目标，但日志里的 dst 能直接指出"这条查询被送到哪里"，
// 排障时不必再从 QNAME 反推。
type udpDNSQuery struct {
	raw   []byte
	msg   *dns.Msg
	src   string
	dst   string
	reply udpReply
}

// handleUDPQuery 处理一条 UDP DNS 查询：Block/缓存/直连三条同步分支交给共享
// 执行器（dns_exec.go），代理分支走本前端自己的异步投递（应答由 receiveLoop
// 在任意时刻送回）。前端因此只负责封帧与投递模型。
func (d *dnsInterceptor) handleUDPQuery(clientAddr *net.UDPAddr, req udpDNSQuery) error {
	plan := d.plan(req.msg)
	ex := dnsExchange{plan: plan, src: req.src, dst: req.dst}

	if plan.action != dnsActionProxy {
		resp, err := d.executeSync(ex, req.msg, req.dst)
		if err != nil {
			return err
		}
		return req.reply.msg(resp)
	}
	return d.proxyUDPQuery(clientAddr, req, ex)
}

// proxyUDPQuery 把一条查询交给经隧道的 UDP 交换。首载荷合并进引导记录时不需要
// 额外发送；后续查询直接复用现有交换。应答由 receiveLoop 异步送回。
func (d *dnsInterceptor) proxyUDPQuery(clientAddr *net.UDPAddr, req udpDNSQuery, ex dnsExchange) error {
	// 上游解析器依据查询里的 EDNS0 尺寸决定应答上限；钳制与重新封包由执行器
	// 统一处理（与 TCP 路径共用同一段逻辑）。
	payload, err := prepareProxied(req.msg, req.raw)
	if err != nil {
		log.Warn("[DNS_PROXY] repack clamped query", "err", err)
		payload = req.raw
	}

	// upstream 是本代理解析查询的位置；客户端请求的是其自身解析器所配置的
	// 服务器，而应答必须伪装成来自该地址（req.dst），与其他所有 DNS 分支
	// 一致。如果改用 upstream 来封装应答，透明 NAT（tun2socks）会把它丢弃：
	// 流是按客户端的目标来标识的，声称来自不同服务器的数据报永远不会匹配，
	// 查询就会看起来没有得到应答。
	upstream := config.ProxyDNSServer
	key := clientAddr.String() + "_" + upstream

	log.Info("[DNS_PROXY]", "domain", ex.plan.domain, "qtype", ex.plan.qtype,
		"src", ex.src, "dst", ex.dst)
	stats.RecordDNSProxyQuery()

	ue, created, err := d.pool.acquireExchange(context.Background(), key, upstream, payload)
	if err != nil {
		log.Error("[UDP_PROXY] open exchange", "dst", upstream, "err", err)
		return err
	}
	onData := func(data []byte) {
		if req.reply.raw != nil {
			req.reply.raw(d.postProcessProxied(data, ex.src, ex.dst))
		}
	}
	if created {
		go d.pool.receiveLoop(ue, key, d.respTimeout, onData)
		return nil // 第一个载荷已在握手中发送
	}

	if err := ue.Send(payload); err != nil {
		log.Error("[UDP_PROXY] send", "err", err)
		d.pool.removeExchange(key, ue)
		return err
	}
	return nil
}
