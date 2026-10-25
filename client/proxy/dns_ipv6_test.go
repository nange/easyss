package proxy

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
)

// IPv6 禁用时 AAAA 没有任何意义：必须在本地返回 NODATA，不能再去上游或隧道查一次。
func TestAAAAQueryReturnsLocalNODATAWhenIPv6Disabled(t *testing.T) {
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	d := &dnsInterceptor{
		router: rt,
		cache:  easydns.NewCache(""),
		dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("AAAA query must not reach an upstream when IPv6 is disabled")
			return nil, context.Canceled
		},
	}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeAAAA)
	query.Id = 0x1234
	raw, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	if got := d.plan(query).action; got != dnsActionEmpty {
		t.Fatalf("plan(AAAA) action = %v, want dnsActionEmpty", got)
	}

	var replied *dns.Msg
	err = d.handleUDPQuery(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}, udpDNSQuery{
		raw: raw,
		msg: query,
		src: "127.0.0.1:5353",
		dst: "8.8.8.8:53",
		reply: udpReply{msg: func(m *dns.Msg) error {
			replied = m
			return nil
		}},
	})
	if err != nil {
		t.Fatalf("handleUDPQuery: %v", err)
	}
	if replied == nil {
		t.Fatal("no reply")
	}
	if !replied.Response || replied.Rcode != dns.RcodeSuccess {
		t.Fatalf("reply = response %v, rcode %d; want NOERROR response", replied.Response, replied.Rcode)
	}
	if replied.Id != query.Id || len(replied.Question) != 1 || replied.Question[0].Qtype != dns.TypeAAAA {
		t.Fatalf("reply does not echo the AAAA query: %+v", replied)
	}
	if len(replied.Answer) != 0 || len(replied.Ns) != 0 || len(replied.Extra) != 0 {
		t.Fatalf("reply must be an empty NODATA, got %+v", replied)
	}

	// A 查询不受影响；IPv6 启用时 AAAA 也不能被这个短路吞掉。
	aQuery := new(dns.Msg)
	aQuery.SetQuestion("example.com.", dns.TypeA)
	if got := d.plan(aQuery).action; got == dnsActionEmpty {
		t.Fatalf("plan(A) action = %v, want a normal route", got)
	}

	rt6, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleEnable})
	if err != nil {
		t.Fatalf("router.New(ipv6 enable): %v", err)
	}
	d6 := &dnsInterceptor{router: rt6, cache: easydns.NewCache("")}
	if got := d6.plan(query).action; got == dnsActionEmpty {
		t.Fatalf("plan(AAAA) action = %v with IPv6 enabled, want a normal route", got)
	}
}
