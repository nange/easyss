package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DNSMsgTypeA sends a DNS A record query for domain to the specified server.
func DNSMsgTypeA(dnsServer, domain string) (*dns.Msg, error) {
	return queryMsg(context.Background(), dns.TypeA, dnsServer, domain)
}

// DNSMsgTypeAAAA sends a DNS AAAA record query for domain to the specified server.
func DNSMsgTypeAAAA(dnsServer, domain string) (*dns.Msg, error) {
	return queryMsg(context.Background(), dns.TypeAAAA, dnsServer, domain)
}

// DNSMsgTypeAAAAContext is DNSMsgTypeAAAA bounded by ctx: the query fails as
// soon as the context is done, even if the per-query client timeout (5s) has
// not elapsed. Used by startup paths (server IPv6 resolution) that must not
// stall proxy initialization on unreachable DNS servers.
func DNSMsgTypeAAAAContext(ctx context.Context, dnsServer, domain string) (*dns.Msg, error) {
	return queryMsg(ctx, dns.TypeAAAA, dnsServer, domain)
}

func queryMsg(ctx context.Context, dnsType uint16, dnsServer, domain string) (*dns.Msg, error) {
	c := &dns.Client{UDPSize: 8192, Timeout: 5 * time.Second}

	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dnsType)
	m.RecursionDesired = true

	r, _, err := c.ExchangeContext(ctx, m, dnsServer)
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
	return lookupIPV6From(context.Background(), dnsServer, domain)
}

// LookupIPV6FromContext is LookupIPV6From bounded by ctx (see
// DNSMsgTypeAAAAContext).
func LookupIPV6FromContext(ctx context.Context, dnsServer, domain string) ([]net.IP, error) {
	return lookupIPV6From(ctx, dnsServer, domain)
}

func lookupIPV6From(ctx context.Context, dnsServer, domain string) ([]net.IP, error) {
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
