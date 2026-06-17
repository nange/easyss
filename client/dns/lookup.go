package dns

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DNSMsgTypeA sends a DNS A record query for domain to the specified server.
func DNSMsgTypeA(dnsServer, domain string) (*dns.Msg, error) {
	return queryMsg(dns.TypeA, dnsServer, domain)
}

// DNSMsgTypeAAAA sends a DNS AAAA record query for domain to the specified server.
func DNSMsgTypeAAAA(dnsServer, domain string) (*dns.Msg, error) {
	return queryMsg(dns.TypeAAAA, dnsServer, domain)
}

func queryMsg(dnsType uint16, dnsServer, domain string) (*dns.Msg, error) {
	c := &dns.Client{UDPSize: 8192, Timeout: 5 * time.Second}

	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dnsType)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, dnsServer)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns query response Rcode:%v not equals RcodeSuccess", r.Rcode)
	}

	return r, nil
}

// LookupIPV4From resolves IPv4 addresses for domain from the specified DNS server.
func LookupIPV4From(dnsServer, domain string) ([]net.IP, error) {
	msgA, err := DNSMsgTypeA(dnsServer, domain)
	if err != nil || msgA == nil {
		return nil, err
	}

	var ips []net.IP
	for _, an := range msgA.Answer {
		if a, ok := an.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}

	return ips, nil
}

// LookupIPV6From resolves IPv6 addresses for domain from the specified DNS server.
func LookupIPV6From(dnsServer, domain string) ([]net.IP, error) {
	msgAAAA, err := DNSMsgTypeAAAA(dnsServer, domain)
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
