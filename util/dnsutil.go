package util

import "github.com/miekg/dns"

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
