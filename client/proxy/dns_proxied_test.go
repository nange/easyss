package proxy

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
)

// TestPostProcessProxiedNormalizesEDNS0 固定隧道代理路径也会规范化畸形
// EDNS0 应答：缓存与客户端必须看到同一份修好的报文，否则坏应答会在缓存里
// 停留 1~4 小时。代理路径返回的是原始字节，因此还必须重新 Pack。
func TestPostProcessProxiedNormalizesEDNS0(t *testing.T) {
	rt, err := router.New(router.Config{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	d := &dnsInterceptor{
		router: rt,
		cache:  easydns.NewCache(""),
	}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Answer = []dns.RR{&dns.OPT{Hdr: dns.RR_Header{
		Name: ".", Rrtype: dns.TypeOPT, Class: 4096,
	}}}
	resp.Extra = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name: "example.com.", Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: 60,
		},
		A: net.ParseIP("1.2.3.4"),
	}}
	raw, err := resp.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	gotBytes := d.postProcessProxied(raw, "src", "dst")
	var got dns.Msg
	if err := got.Unpack(gotBytes); err != nil {
		t.Fatalf("unpack processed answer: %v", err)
	}
	if opt := got.IsEdns0(); opt != nil {
		t.Fatalf("OPT record was not removed from the client answer: %v", opt)
	}
	if len(got.Answer) != 1 || got.Answer[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("answer section = %v, want the salvaged A record", got.Answer)
	}

	cached := d.cache.Get("example.com.", "A", false)
	if cached == nil {
		t.Fatal("normalized answer was not cached")
	}
	if opt := cached.IsEdns0(); opt != nil {
		t.Fatalf("OPT record was cached: %v", opt)
	}
	if len(cached.Answer) != 1 || cached.Answer[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("cached answer = %v, want the salvaged A record", cached.Answer)
	}
}
