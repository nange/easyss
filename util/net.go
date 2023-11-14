package util

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

func IsIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func IsLANIP(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}

	return _ip.IsPrivate() || _ip.IsLoopback() || _ip.IsLinkLocalMulticast() || _ip.IsLinkLocalUnicast() ||
		_ip.IsUnspecified() || _ip.IsMulticast() || _ip.IsInterfaceLocalMulticast()
}

func IsLoopbackIP(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}

	return _ip.IsLoopback()
}

func IsIPV6(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}

	if _ip.To4() != nil {
		return false
	} else if _ip.To16() != nil {
		return true
	}

	return false
}

func DNSMsgTypeA(dnsServer, domain string) (*dns.Msg, error) {
	return dnsMsg(dns.TypeA, dnsServer, domain)
}

func DNSMsgTypeAAAA(dnsServer, domain string) (*dns.Msg, error) {
	return dnsMsg(dns.TypeAAAA, dnsServer, domain)
}

func dnsMsg(dnsType uint16, dnsServer, domain string) (*dns.Msg, error) {
	c := &dns.Client{UDPSize: 8192}

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

// LookupIPV4From lookup ipv4s for domain from dnsServer
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

// LookupIPV6From lookup ipv6s for domain from dnsServer
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
