package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	clientconfig "github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/protocol"
)

// 本文件守护"DNS 执行器只有一份"：同一条查询无论从 UDP 还是 TCP 前端进来，
// 都必须产生完全相同的缓存条目与 AAAA 剥离结果。只按前端分开测，一边改错不会
// 让另一边的用例失败。

// TestProxiedPostProcessingIsShared 固定代理分支的后处理只存在于 finishProxied：
// UDP 前端经 postProcessProxied 间接调用它，TCP 前端直接调用它。
func TestProxiedPostProcessingIsShared(t *testing.T) {
	tests := []struct {
		name            string
		ipv6Disabled    bool
		qtype           uint16
		wantAnswerCount int
	}{
		{name: "AAAA 查询在 ipv6 关闭时被剥离", ipv6Disabled: true, qtype: dns.TypeAAAA, wantAnswerCount: 0},
		{name: "AAAA 查询在 ipv6 启用时保留", ipv6Disabled: false, qtype: dns.TypeAAAA, wantAnswerCount: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipv6Rule := router.IPV6RuleEnable
			if tt.ipv6Disabled {
				ipv6Rule = router.IPV6RuleDisable
			}
			rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: ipv6Rule})
			if err != nil {
				t.Fatalf("router.New: %v", err)
			}

			d := &dnsInterceptor{router: rt, cache: easydns.NewCache("")}

			query := new(dns.Msg)
			query.SetQuestion("example.com.", tt.qtype)
			resp := new(dns.Msg)
			resp.SetReply(query)
			if tt.qtype == dns.TypeAAAA {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: net.ParseIP("2001:db8::1"),
				})
			} else {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("1.2.3.4"),
				})
			}
			raw, err := resp.Pack()
			if err != nil {
				t.Fatalf("pack: %v", err)
			}

			// UDP 前端路径：拿到原始字节，后处理由 postProcessProxied 完成。
			udpBytes := d.postProcessProxied(raw, "src", "dst")
			udpMsg := new(dns.Msg)
			if err := udpMsg.Unpack(udpBytes); err != nil {
				t.Fatalf("unpack udp result: %v", err)
			}

			// TCP 前端路径：拿到消息对象，后处理由 finishProxied 完成。
			tcpMsg := new(dns.Msg)
			if err := tcpMsg.Unpack(raw); err != nil {
				t.Fatalf("unpack raw: %v", err)
			}
			d.finishProxied(tcpMsg, "example.com", "src", "dst")

			if len(udpMsg.Answer) != tt.wantAnswerCount {
				t.Errorf("udp answers = %d, want %d", len(udpMsg.Answer), tt.wantAnswerCount)
			}
			if len(tcpMsg.Answer) != tt.wantAnswerCount {
				t.Errorf("tcp answers = %d, want %d", len(tcpMsg.Answer), tt.wantAnswerCount)
			}

			// 两条路径写入的缓存条目必须一致，且都反映剥离后的结果。
			cached := d.cache.Get("example.com.", dns.TypeToString[tt.qtype], false)
			if cached == nil {
				t.Fatal("answer was not cached")
			}
			if len(cached.Answer) != tt.wantAnswerCount {
				t.Errorf("cached answers = %d, want %d", len(cached.Answer), tt.wantAnswerCount)
			}
		})
	}
}

// TestPrepareProxiedClampsEDNS0 固定两个前端共用的查询前处理：宣告的 EDNS0
// 尺寸被钳到隧道预算内，且未改动时原样复用调用方已有的字节。
func TestPrepareProxiedClampsEDNS0(t *testing.T) {
	t.Run("已有字节且无需钳制时原样复用", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		raw, err := msg.Pack()
		if err != nil {
			t.Fatalf("pack: %v", err)
		}
		got, err := prepareProxied(msg, raw)
		if err != nil {
			t.Fatalf("prepareProxied: %v", err)
		}
		if len(got) != len(raw) || &got[0] != &raw[0] {
			t.Error("raw payload should be reused verbatim when no clamping is needed")
		}
	})

	t.Run("声明超大 EDNS0 时钳制并重打包", func(t *testing.T) {
		msg := new(dns.Msg)
		msg.SetQuestion("example.com.", dns.TypeA)
		msg.SetEdns0(65535, false)

		got, err := prepareProxied(msg, nil)
		if err != nil {
			t.Fatalf("prepareProxied: %v", err)
		}
		unpacked := new(dns.Msg)
		if err := unpacked.Unpack(got); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		opt := unpacked.IsEdns0()
		if opt == nil {
			t.Fatal("EDNS0 option was dropped instead of clamped")
		}
		if opt.UDPSize() > protocol.MaxUDPDataSize {
			t.Errorf("advertised UDP size = %d, want <= %d", opt.UDPSize(), protocol.MaxUDPDataSize)
		}
	})
}

// TestExecuteSyncBlockAndCacheHit 固定同步分支里两条不应触碰网络的路径。
func TestExecuteSyncBlockAndCacheHit(t *testing.T) {
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	d := &dnsInterceptor{
		router: rt,
		cache:  easydns.NewCache(""),
		// 任何网络访问都应让测试失败。
		dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("executeSync must not dial for block/cache-hit actions")
			return nil, net.ErrClosed
		},
	}

	query := new(dns.Msg)
	query.SetQuestion("blocked.example.", dns.TypeA)
	query.Id = 0x7777

	resp, err := d.executeSync(dnsExchange{plan: dnsPlan{action: dnsActionBlock, domain: "blocked.example"}, src: "src", dst: "dst"}, query, "")
	if err != nil {
		t.Fatalf("executeSync(block): %v", err)
	}
	if !resp.Response || len(resp.Answer) != 0 {
		t.Errorf("blocked reply = %+v, want a response with no answers", resp)
	}

	cached := new(dns.Msg)
	cached.SetReply(query)
	resp, err = d.executeSync(dnsExchange{
		plan: dnsPlan{action: dnsActionCacheHit, cached: cached}, src: "src", dst: "dst",
	}, query, "")
	if err != nil {
		t.Fatalf("executeSync(cache-hit): %v", err)
	}
	if resp != cached {
		t.Error("cache-hit must return the cached message as-is")
	}

	// proxy 动作不是同步分支：必须是显式的错误，而不是静默返回 nil。
	if _, err := d.executeSync(dnsExchange{plan: dnsPlan{action: dnsActionProxy}}, query, ""); err == nil {
		t.Error("executeSync(proxy) must report that the action is handled by the frontend")
	}
}

// TestDirectBranchIsShared 固定直连分支也走同一个执行器：查询送达客户端显式
// 指定的解析器，应答进入直连缓存（与代理缓存分开）。
func TestDirectBranchIsShared(t *testing.T) {
	easydns.ResetResolveState()
	responder := startUDPDNSResponderAny(t, "9.9.9.9")
	oldDNS := clientconfig.DirectDNSServers
	clientconfig.DirectDNSServers = []string{responder}
	t.Cleanup(func() { clientconfig.DirectDNSServers = oldDNS })

	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	d := &dnsInterceptor{
		router: rt,
		cache:  easydns.NewCache(""),
		dial: func(_ context.Context, network, addr string) (net.Conn, error) {
			var nd net.Dialer
			return nd.Dial(network, addr)
		},
		dialTimeout: 2 * time.Second,
	}

	query := new(dns.Msg)
	query.SetQuestion("direct.example.com.", dns.TypeA)
	query.Id = 0x1234

	plan := dnsPlan{action: dnsActionDirect, domain: "direct.example.com", qtype: "A"}
	resp, err := d.executeSync(dnsExchange{plan: plan, src: "src", dst: responder}, query, responder)
	if err != nil {
		t.Fatalf("executeSync(direct): %v", err)
	}
	if resp.Id != query.Id {
		t.Errorf("reply Id = %#x, want %#x", resp.Id, query.Id)
	}

	cached := d.cache.Get("direct.example.com.", "A", true)
	if cached == nil {
		t.Fatal("direct answer was not cached")
	}
	if len(cached.Answer) != 1 {
		t.Fatalf("cached answers = %d, want 1", len(cached.Answer))
	}
	if a, ok := cached.Answer[0].(*dns.A); !ok || a.A.String() != "9.9.9.9" {
		t.Errorf("cached answer = %v, want 9.9.9.9", cached.Answer[0])
	}
}
