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

// 本文件是 DNS 拦截的**执行器**：把 dnsPlan 的四种动作（Block / 缓存命中 /
// 直连解析 / 经隧道代理）变成具体结果。
//
// 分流判定早已共享（dns.go 的 plan），但"动作 → 结果"此前是两份：UDP 前端在
// dns_udp.go 里逐行实现，TCP 前端在 dns_tcp.go 的 tcpDNSSession.resolve 里
// 又抄了一遍。两份已经在细节上漂移——代理应答的规范化、重新封包、日志里的
// 域名来源都不同——于是任何一步（比如"再加一次 AAAA 剥离"）都容易只改一边。
//
// 现在结构是：前端只负责**封帧与投递模型**
//   - UDP：异步。代理分支的应答由 receiveLoop 在任意时刻送回，前端提供 onData；
//   - TCP：同步。一条连接顺序使用自己的交换，阻塞等待应答。
//
// 两者共用 executeSync（同步分支）与 prepareProxied/finishProxied（代理分支的
// 前后两段）。投递模型**不**合并：把 UDP 改成阻塞等待会丢掉多应答/重传语义，
// 把 TCP 改成回调也没有收益。

type dnsActionError struct{ action dnsAction }

func (e dnsActionError) Error() string {
	return "dns: action " + e.action.String() + " is not handled synchronously"
}

func (a dnsAction) String() string {
	switch a {
	case dnsActionBlock:
		return "block"
	case dnsActionCacheHit:
		return "cache-hit"
	case dnsActionDirect:
		return "direct"
	default:
		return "proxy"
	}
}

// errDNSResponseTimeout 表示代理 DNS 上游在等待窗口内没有任何应答。
var errDNSResponseTimeout = errors.New("dns response timeout")

// dnsExchange 描述一次查询的上下文：分流结果与两侧地址（只用于日志）。
type dnsExchange struct {
	plan dnsPlan
	src  string
	dst  string
}

// executeSync 执行不需要等待隧道往返的三条分支：Block、缓存命中、直连解析。
// 调用方必须已经用 plan 判定过动作，并且**只**在 action 不是 proxy 时调用它
// ——代理分支的投递模型由各前端自理（见文件头注释）。
//
// reqServer 是客户端显式指定的解析器（可为空），只有直连分支使用它。
// 返回的应答已经把 Id 改写为本次查询的 Id。
func (d *dnsInterceptor) executeSync(ex dnsExchange, msg *dns.Msg, reqServer string) (*dns.Msg, error) {
	switch ex.plan.action {
	case dnsActionBlock:
		log.Info("[DNS_BLOCK] blocked", "domain", ex.plan.domain, "qtype", ex.plan.qtype,
			"src", ex.src, "dst", ex.dst)
		return blockedDNSReply(msg), nil

	case dnsActionCacheHit:
		return ex.plan.cached, nil

	case dnsActionDirect:
		log.Info("[DNS_DIRECT]", "domain", ex.plan.domain, "qtype", ex.plan.qtype,
			"src", ex.src, "dst", ex.dst)
		stats.RecordDNSDirectQuery()
		resp, err := d.resolveDirectDNS(msg, ex.plan.domain, reqServer)
		if err != nil {
			log.Error("[DNS_DIRECT]", "domain", ex.plan.domain, "err", err,
				"src", ex.src, "dst", ex.dst)
			return nil, err
		}
		log.Info("[DNS_DIRECT] result", "domain", ex.plan.domain, "qtype", ex.plan.qtype,
			"answers", util.DNSAnswerStrings(resp), "src", ex.src, "dst", ex.dst)
		resp.Id = msg.Id
		return resp, nil

	default:
		return nil, dnsActionError{action: ex.plan.action}
	}
}

// prepareProxied 把一条查询准备成经隧道发送的字节串：把宣告的 EDNS0 接收尺寸
// 钳到隧道数据报预算内（否则上游可以合法地发出超过服务端读缓冲的应答），然后
// 按需重新打包。
//
// raw 是调用方手里已有的序列化结果（UDP 前端手里就是原始数据报）；未钳制时
// 直接复用它，省掉一次 Pack。raw 为 nil（TCP 前端只有消息对象）或钳制发生
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

// finishProxied 是一条代理 DNS 应答的**唯一**后处理入口：规范化畸形 EDNS0、
// 按 ipv6 策略剥离 AAAA、写入代理缓存、记录结果并按自定义域名规则学习答案。
//
// 返回 true 表示消息被改写，调用方在使用原始字节（UDP 路径）时必须重新 Pack，
// 否则客户端与缓存会看到两份不同的报文。changed 的语义因此同时覆盖"规范化"
// 与"AAAA 剥离"，不再由两个前端各自维护。
func (d *dnsInterceptor) finishProxied(msg *dns.Msg, domain, src, dst string) bool {
	// guard 必须在任何改写之前：没有 Question 的应答不是一次可归属的解析结果
	// （缓存会写入一条没有键的消息，学习会拿错域名），整条丢弃。放在归一化之后
	// 会让"已发生的改写"与返回的 changed 不一致，TCP 前端（直接 Pack msg）与
	// UDP 前端（原样返回字节）就会发出不同的报文——正是本文件要消灭的那类漂移。
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

	log.Info("[DNS_PROXY] result", "domain", domain, "qtype", dns.TypeToString[qtype],
		"answers", util.DNSAnswerStrings(msg), "src", src, "dst", dst)

	d.learnDNSAnswers(msg, domain, false)
	return changed
}

// postProcessProxied 是 finishProxied 的字节流包装：UDP 前端拿到的是原始
// 数据报，因此这里负责解包、后处理，并在改动后重新封包。解包失败或不是响应
// 时原样返回（不缓存、不学习）。
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
