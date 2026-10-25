package proxy

import (
	"errors"

	"github.com/miekg/dns"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/rule"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
)

// 本文件是 DNS 拦截的执行器：把 dnsPlan 的五种动作变成具体结果，供 UDP 与 TCP 两个前端
// 共用。前端只负责封帧与投递模型——UDP 异步（应答由 receiveLoop 送回），TCP 同步（阻塞等
// 自己的交换）。投递模型不合并：把 UDP 改成阻塞等待会丢掉多应答/重传语义。

type dnsActionError struct{ action dnsAction }

func (e dnsActionError) Error() string {
	return "dns: action " + e.action.String() + " is not handled synchronously"
}

func (a dnsAction) String() string {
	switch a {
	case dnsActionBlock:
		return "block"
	case dnsActionEmpty:
		return "empty"
	case dnsActionCacheHit:
		return "cache-hit"
	case dnsActionDirect:
		return "direct"
	default:
		return "proxy"
	}
}

var errDNSResponseTimeout = errors.New("dns response timeout")

type dnsExchange struct {
	plan dnsPlan
	src  string
	dst  string
}

// executeSync 执行不需要等待隧道往返的四条分支：Block、IPv6 禁用空应答、缓存命中、直连解析。调用方必须
// 只用非 proxy 的动作调用它，代理分支的投递模型由各前端自理。reqServer 是客户端显式
// 指定的解析器，只有直连分支使用。返回的应答已把 Id 改写为本次查询的 Id。
func (d *dnsInterceptor) executeSync(ex dnsExchange, msg *dns.Msg, reqServer string) (*dns.Msg, error) {
	switch ex.plan.action {
	case dnsActionBlock:
		log.Info("[DNS_BLOCK] blocked", "domain", ex.plan.domain, "qtype", ex.plan.qtype,
			"src", ex.src, "dst", ex.dst)
		return blockedDNSReply(msg), nil

	case dnsActionEmpty:
		log.Debug("[DNS_IPV6_DISABLED] empty AAAA answer", "domain", ex.plan.domain,
			"src", ex.src, "dst", ex.dst)
		return emptyDNSReply(msg), nil

	case dnsActionCacheHit:
		return ex.plan.cached, nil

	case dnsActionDirect:
		log.Debug("[DNS_DIRECT]", "domain", ex.plan.domain, "qtype", ex.plan.qtype,
			"src", ex.src, "dst", ex.dst)
		stats.RecordDNSDirectQuery()
		resp, err := d.resolveDirectDNS(msg, ex.plan.domain, reqServer)
		if err != nil {
			log.Error("[DNS_DIRECT]", "domain", ex.plan.domain, "err", err,
				"src", ex.src, "dst", ex.dst)
			return nil, err
		}
		log.Debug("[DNS_DIRECT] result", "domain", ex.plan.domain, "qtype", ex.plan.qtype,
			"answers", util.DNSAnswerStrings(resp), "src", ex.src, "dst", ex.dst)
		resp.Id = msg.Id
		return resp, nil

	default:
		return nil, dnsActionError{action: ex.plan.action}
	}
}

// prepareProxied 把查询准备成经隧道发送的字节串，先把宣称的 EDNS0 接收尺寸钳到隧道
// 数据报预算内。raw 是调用方已有的序列化结果，未钳制时直接复用；raw 为 nil 或发生钳制
// 时重新打包。
func prepareProxied(msg *dns.Msg, raw []byte) ([]byte, error) {
	clamped := clampDNSEDNS0(msg)
	if !clamped && raw != nil {
		return raw, nil
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	return packed, nil
}

// finishProxied 是代理 DNS 应答唯一的后处理入口：规范化畸形 EDNS0、按 ipv6 策略剥离
// AAAA、写代理缓存、记录结果并按自定义域名规则学习答案。返回 true 表示消息被改写，使用
// 原始字节的调用方必须重新 Pack，否则客户端与缓存会看到两份不同的报文。
func (d *dnsInterceptor) finishProxied(msg *dns.Msg, domain, src, dst string) bool {
	// 这个检查必须在任何改写之前：没有 Question 的应答无法归属（缓存会写入没有键的
	// 消息，学习会拿错域名），整条丢弃。
	if msg == nil || len(msg.Question) == 0 {
		return false
	}
	changed := easydns.NormalizeEDNS0Answer(msg)
	qtype := msg.Question[0].Qtype
	if d.router.ShouldIPV6Disable() && qtype == dns.TypeAAAA {
		msg.Answer = nil
		changed = true
	}
	_ = d.cache.Set(msg, false)

	log.Debug("[DNS_PROXY] result", "domain", domain, "qtype", dns.TypeToString[qtype],
		"answers", util.DNSAnswerStrings(msg), "src", src, "dst", dst)

	d.learnDNSAnswers(msg, domain, false)
	return changed
}

// postProcessProxied 是 finishProxied 的字节流包装：解包、后处理，并在改动后重新封包。
// 解包失败或不是响应时原样返回。
func (d *dnsInterceptor) postProcessProxied(data []byte, src, dst string) []byte {
	msg := &dns.Msg{}
	if err := msg.Unpack(data); err != nil || !util.IsDNSResponse(msg) || len(msg.Question) == 0 {
		return data
	}
	domain := rule.NormalizeHost(msg.Question[0].Name)
	if d.finishProxied(msg, domain, src, dst) {
		if packed, err := msg.Pack(); err == nil {
			data = packed
		} else {
			log.Warn("[DNS_PROXY] repack normalized answer", "err", err)
		}
	}
	return data
}
