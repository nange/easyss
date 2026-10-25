package util

import (
	"strings"

	"github.com/miekg/dns"
)

// IsDNSRequest 报告 msg 是否为 DNS 查询，不限制 qtype。客户端拦截与服务端按 QNAME
// 路由必须共用同一判定（HTTPS/SVCB 等现代查询同样算）；只处理 A/AAAA 的缓存与学习
// 路径应自行检查 Question[0].Qtype。
func IsDNSRequest(msg *dns.Msg) bool {
	return msg != nil && len(msg.Question) > 0 && !msg.Response
}

func IsDNSResponse(msg *dns.Msg) bool {
	if len(msg.Question) == 0 {
		return false
	}
	return msg.Response
}

// DNSAnswerStrings 以 "A:1.2.3.4" 这类形式返回最多 10 条答案记录。
func DNSAnswerStrings(msg *dns.Msg) []string {
	var results []string
	ForEachDNSAnswer(msg, func(kind, value string) {
		if len(results) < 10 {
			results = append(results, kind+":"+value)
		}
	})
	return results
}

// 对每条 A、AAAA、CNAME 答案调用 fn（CNAME 目标去掉末尾点号）；客户端与服务端
// 动态路由共用这唯一的遍历入口。
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
