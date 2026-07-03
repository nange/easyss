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

// DNSAnswerStrings extracts answer records from a DNS response as human-readable
// strings like "A:1.2.3.4", "AAAA:2001::1", "CNAME:example.com". Returns at most
// 10 entries.
func DNSAnswerStrings(msg *dns.Msg) []string {
	var results []string
	for _, ans := range msg.Answer {
		if len(results) >= 10 {
			break
		}
		switch a := ans.(type) {
		case *dns.A:
			results = append(results, "A:"+a.A.String())
		case *dns.AAAA:
			results = append(results, "AAAA:"+a.AAAA.String())
		case *dns.CNAME:
			results = append(results, "CNAME:"+strings.TrimSuffix(a.Target, "."))
		}
	}
	return results
}
