package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/nange/easyss/v3/log"
)

// DNSMsgTypeAContext 向指定服务器发送 domain 的 DNS A 记录查询。
// 它是受 ctx 约束的查询：只要 context 结束查询即失败，即使单次查询的客户端
// 超时（dnsQueryTimeout）尚未到。所有调用方都是启动/预解析路径，它们不能在
// 不可达的 DNS 服务器上阻塞代理初始化。
func DNSMsgTypeAContext(ctx context.Context, dnsServer, domain string) (*dns.Msg, error) {
	return queryMsg(ctx, dns.TypeA, dnsServer, domain)
}

// DNSMsgTypeAAAAContext 是 DNSMsgTypeAContext 的 AAAA 版本。
func DNSMsgTypeAAAAContext(ctx context.Context, dnsServer, domain string) (*dns.Msg, error) {
	return queryMsg(ctx, dns.TypeAAAA, dnsServer, domain)
}

func queryMsg(ctx context.Context, dnsType uint16, dnsServer, domain string) (*dns.Msg, error) {
	c := &dns.Client{UDPSize: 8192, Timeout: dnsQueryTimeout}

	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dnsType)
	m.RecursionDesired = true

	r, _, err := c.ExchangeContext(ctx, m, dnsServer)
	if err != nil {
		return nil, err
	}
	normalizeEDNS0Answer(r)
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns query response Rcode:%v not equals RcodeSuccess", r.Rcode)
	}

	return r, nil
}

// normalizeEDNS0Answer 规范化应答里的 OPT 记录，使报文既可以被严格解析器接受，
// 也可以被安全地缓存后回放给客户端。
//
// 部分家用路由器/缓存的 EDNS0 应答会把 OPT 记录放进 ANSWER 段并使头部计数不
// 自洽（ancount 只覆盖排在第一位的那条 OPT），真正的 A/AAAA 记录被挤到
// ADDITIONAL 段。严格解析器（dig/BIND）会直接判为畸形报文，宽松解析器（Go
// 标准库解析器）则只看到一条 41 类型记录、拿不到任何地址——现象是"域名解析
// 不到"（no such host），而同一台服务器对不带 EDNS0 的查询却一切正常。
// 这里把 ADDITIONAL 段里同名的请求类型记录搬回 ANSWER 段，并丢弃 OPT。
//
// 本包的查询从不带 EDNS0，因此应答里的 OPT 没有任何调用方需要：留着它只会让
// 缓存下来的应答在回放给客户端时多出一条它们没有请求过的 OPT。
func normalizeEDNS0Answer(msg *dns.Msg) {
	if msg == nil || len(msg.Question) == 0 {
		return
	}

	optInAnswer := false
	answers := msg.Answer[:0]
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeOPT {
			optInAnswer = true
			continue
		}
		answers = append(answers, rr)
	}
	msg.Answer = answers

	if optInAnswer {
		q := msg.Question[0]
		var salvaged []dns.RR
		extra := msg.Extra[:0]
		for _, rr := range msg.Extra {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			// ADDITIONAL 段里同名的请求类型记录几乎只可能来自上面那种头部
			// 计数错位，因此当作被挤走的答案回收。
			if h.Rrtype == q.Qtype && strings.EqualFold(h.Name, q.Name) {
				salvaged = append(salvaged, rr)
				continue
			}
			extra = append(extra, rr)
		}
		msg.Extra = extra
		msg.Answer = append(msg.Answer, salvaged...)
		log.Debug("[DNS] normalized malformed edns0 answer (OPT in the answer section)",
			"name", q.Name, "qtype", dns.TypeToString[q.Qtype], "salvaged", len(salvaged))
	}

	extra := msg.Extra[:0]
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	msg.Extra = extra
}

// LookupIPV6FromContext 从指定的 DNS 服务器解析 domain 的 IPv6 地址，受 ctx
// 约束（见 DNSMsgTypeAContext）。
// 服务器应答 NODATA（NOERROR 但没有 AAAA 记录）时返回空列表且不报错：
// "解析器可达但没有该记录"与"解析失败"是两件事，调用方据此区分可达性。
func LookupIPV6FromContext(ctx context.Context, dnsServer, domain string) ([]net.IP, error) {
	msgAAAA, err := DNSMsgTypeAAAAContext(ctx, dnsServer, domain)
	if err != nil || msgAAAA == nil {
		return nil, err
	}

	var ips []net.IP
	for _, an := range msgAAAA.Answer {
		if a, ok := an.(*dns.AAAA); ok {
			ips = append(ips, a.AAAA)
		}
	}

	return ips, nil
}
