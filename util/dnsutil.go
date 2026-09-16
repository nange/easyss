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
	ForEachDNSAnswer(msg, func(kind, value string) {
		if len(results) < 10 {
			results = append(results, kind+":"+value)
		}
	})
	return results
}

// ForEachDNSAnswer calls fn for every A, AAAA and CNAME answer record, with
// kind one of "A", "AAAA" or "CNAME" and value the address or the
// dot-trimmed target. It is the single walker for the answer lists consumed by
// the client's and the server's dynamic routing (both used to carry their own
// copy of this switch).
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
