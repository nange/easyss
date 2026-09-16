package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DNSMsgTypeA 向指定服务器发送 domain 的 DNS A 记录查询。
func DNSMsgTypeA(dnsServer, domain string) (*dns.Msg, error) {
	return queryMsg(context.Background(), dns.TypeA, dnsServer, domain)
}

// DNSMsgTypeAContext 是受 ctx 约束的 DNSMsgTypeA：只要 context 结束查询即
// 失败，即使单次查询的客户端超时（5s）尚未到。用于启动路径（服务器域名预
// 解析），这些路径不能在不可达的 DNS 服务器上阻塞代理初始化。
func DNSMsgTypeAContext(ctx context.Context, dnsServer, domain string) (*dns.Msg, error) {
	return queryMsg(ctx, dns.TypeA, dnsServer, domain)
}

// DNSMsgTypeAAAA 向指定服务器发送 domain 的 DNS AAAA 记录查询。
func DNSMsgTypeAAAA(dnsServer, domain string) (*dns.Msg, error) {
	return queryMsg(context.Background(), dns.TypeAAAA, dnsServer, domain)
}

// DNSMsgTypeAAAAContext 是受 ctx 约束的 DNSMsgTypeAAAA：只要 context 结束
// 查询即失败，即使单次查询的客户端超时（5s）尚未到。用于启动路径（服务器
// IPv6 解析），这些路径不能在不可达的 DNS 服务器上阻塞代理初始化。
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

// LookupIPV4From 从指定的 DNS 服务器解析 domain 的 IPv4 地址。
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

// LookupIPV6From 从指定的 DNS 服务器解析 domain 的 IPv6 地址。
func LookupIPV6From(dnsServer, domain string) ([]net.IP, error) {
	return lookupIPV6From(context.Background(), dnsServer, domain)
}

// LookupIPV6FromContext 是受 ctx 约束的 LookupIPV6From（参见
// DNSMsgTypeAAAAContext）。
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
