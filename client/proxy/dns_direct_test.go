package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestExchangeDirectDNSNormalizesEDNS0Answer 固定直连 DNS 拦截路径也会规范化
// 畸形 EDNS0 应答：拦截器自己手写 dns.Conn 往返时也必须调用
// NormalizeEDNS0Answer。漏掉它，家用路由器把 OPT 放进 ANSWER 段的应答会被原样
// 写入缓存（TTL 1~4 小时），后续重试全部命中坏缓存。
func TestExchangeDirectDNSNormalizesEDNS0Answer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			serverErr <- err
			return
		}
		var query dns.Msg
		if err := query.Unpack(buf[:n]); err != nil {
			serverErr <- err
			return
		}

		resp := new(dns.Msg)
		resp.SetReply(&query)
		// 畸形形态：OPT 在 ANSWER 段，真正的 A 记录被挤到 ADDITIONAL。
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
		packed, err := resp.Pack()
		if err != nil {
			serverErr <- err
			return
		}
		_, err = pc.WriteTo(packed, addr)
		serverErr <- err
	}()

	d := &dnsInterceptor{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var nd net.Dialer
			return nd.DialContext(ctx, network, addr)
		},
		dialTimeout: time.Second,
	}
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	resp, err := d.exchangeDirectDNS(context.Background(), query, pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("exchangeDirectDNS: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("dns server: %v", err)
	}

	if opt := resp.IsEdns0(); opt != nil {
		t.Fatalf("OPT record was not removed: %v", opt)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("answer section = %v, want the salvaged A record", resp.Answer)
	}
	if len(resp.Extra) != 0 {
		t.Fatalf("additional section = %v, want empty", resp.Extra)
	}
}
