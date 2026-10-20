package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/nange/easyss/v3/log"
)

// DNSMsgTypeAContext 向指定服务器发送 domain 的 A 记录查询，受 ctx 约束：ctx 结束即失败，
// 即使单次往返的 dnsQueryTimeout 还没到——启动/预解析路径不能在不可达的 DNS 上阻塞初始化。
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
	NormalizeEDNS0Answer(r)
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns query response Rcode:%v not equals RcodeSuccess", r.Rcode)
	}

	return r, nil
}

// 丢弃应答里的 OPT，并把被挤到 ADDITIONAL 段的同名答案搬回 ANSWER：部分家用路由器把 OPT 放进
// ANSWER 且 ancount 只覆盖它，Go 标准库只看到类型 41 记录、拿不到地址（表现为 no such host）；
// 返回是否改动消息，直接转发字节流的调用方须在 true 时重新 Pack。
func NormalizeEDNS0Answer(msg *dns.Msg) bool {
	if msg == nil || len(msg.Question) == 0 {
		return false
	}

	changed := false
	optInAnswer := false
	answers := msg.Answer[:0]
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == dns.TypeOPT {
			optInAnswer = true
			changed = true
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
			// ADDITIONAL 段里同名的请求类型记录几乎只可能来自上面那种头部计数错位。
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
		if rr.Header().Rrtype == dns.TypeOPT {
			changed = true
			continue
		}
		extra = append(extra, rr)
	}
	msg.Extra = extra
	return changed
}

// LookupIPV6FromContext 受 ctx 约束（见 DNSMsgTypeAContext）。服务器应答 NODATA
// （NOERROR 但没有 AAAA 记录）时返回空列表且不报错，调用方据此区分可达性与解析失败。
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
