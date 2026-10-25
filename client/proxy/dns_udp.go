package proxy

import (
	"context"
	"net"

	"github.com/miekg/dns"
	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

// msg 供同步分支（屏蔽/缓存/直连）使用，raw 供异步的代理分支使用（应答由
// udpPool.receiveLoop 在任意时刻送回）；组帧由前端负责，SOCKS5 数据报要按客户端目标封装。
type udpReply struct {
	msg func(*dns.Msg) error
	raw func([]byte)
}

// raw 是原始数据报载荷，用于经隧道发出（首载荷会合并进引导记录）；src/dst 只用于日志，
// dst 能直接指出这条查询被送到哪里，排障不必再从 QNAME 反推。
type udpDNSQuery struct {
	raw   []byte
	msg   *dns.Msg
	src   string
	dst   string
	reply udpReply
}

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

// 首载荷合并进引导记录，不需要额外发送；后续查询复用现有交换，应答由 receiveLoop 异步送回。
func (d *dnsInterceptor) proxyUDPQuery(clientAddr *net.UDPAddr, req udpDNSQuery, ex dnsExchange) error {
	// 上游解析器依据查询里的 EDNS0 尺寸决定应答上限；钳制与重新封包由执行器
	// 统一处理（与 TCP 路径共用同一段逻辑）。
	payload, err := prepareProxied(req.msg, req.raw)
	if err != nil {
		log.Warn("[DNS_PROXY] repack clamped query", "err", err)
		payload = req.raw
	}

	// 应答必须伪装成来自 req.dst（客户端配置的解析器）而不是 upstream：流按客户端目标
	// 标识，透明 NAT（tun2socks）会丢弃源地址不匹配的数据报，查询就看起来没有应答。
	upstream := clientconfig.ProxyDNSServer
	key := clientAddr.String() + "_" + upstream

	log.Debug("[DNS_PROXY]", "domain", ex.plan.domain, "qtype", ex.plan.qtype,
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
