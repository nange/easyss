package util

import (
	"strings"

	"github.com/miekg/dns"
)

func IsDNSRequest(msg *dns.Msg) bool {
	if len(msg.Question) == 0 {
		return false
	}
	q := msg.Question[0]
	return (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) && !msg.Response
}

func IsDNSResponse(msg *dns.Msg) bool {
	if len(msg.Question) == 0 {
		return false
	}
	return msg.Response
}

// DNSAnswerStrings 从 DNS 响应中提取答案记录，格式为人类可读的
// 字符串，如 "A:1.2.3.4"、"AAAA:2001::1"、"CNAME:example.com"。最多
// 返回 10 条。
func DNSAnswerStrings(msg *dns.Msg) []string {
	var results []string
	ForEachDNSAnswer(msg, func(kind, value string) {
		if len(results) < 10 {
			results = append(results, kind+":"+value)
		}
	})
	return results
}

// ForEachDNSAnswer 对每条 A、AAAA 和 CNAME 答案记录调用 fn，
// kind 为 "A"、"AAAA" 或 "CNAME" 之一，value 为地址或去掉末尾点号的
// CNAME 目标。客户端与服务端动态路由都要遍历答案列表，这里是唯一的
// 遍历入口（两端各自维护一份该 switch 的副本）。
func ForEachDNSAnswer(msg *dns.Msg, fn func(kind, value string)) {
	for _, ans := range msg.Answer {
		switch a := ans.(type) {
		case *dns.A:
			fn("A", a.A.String())
		case *dns.AAAA:
			fn("AAAA", a.AAAA.String())
		case *dns.CNAME:
			fn("CNAME", strings.TrimSuffix(a.Target, "."))
		}
	}
}
