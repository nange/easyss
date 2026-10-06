package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// vpnDialOnlyRoute 只实现 VPNRoute（没有 ResolveStatic），用于断言可选能力缺席时
// 静态应答整体关闭（DNS 路径行为与引入该能力之前一致）。
type vpnDialOnlyRoute struct{}

func (vpnDialOnlyRoute) Lookup(string) (string, bool) { return "", false }
func (vpnDialOnlyRoute) DialTCP(context.Context, string) (net.Conn, error) {
	return nil, errors.New("unused")
}
func (vpnDialOnlyRoute) DialUDP(context.Context, string) (net.Conn, error) {
	return nil, errors.New("unused")
}

// staticTestVPN 是配置了对端名字的访问侧替身：VPNRoute（见 fakeVPNRoute）加可选
// 的静态名能力。
func staticTestVPN(peer string, addr netip.Addr) *fakeVPNRoute {
	return &fakeVPNRoute{
		peers:  map[string]string{peer: peer},
		static: map[string]netip.Addr{peer: addr},
	}
}

// TestDNSInterceptorAnswersPeerNamesLocally 是 TUN 模式透明访问的 DNS 前提：
// 系统解析器在 TUN 下指向的是公网 DNS（见 client/tun 的 splitDNS 步骤），那些
// 查询经 tun2socks 到达本拦截器，因此对端名字必须在这里被就地应答——而不是在
// client/dns 的转发服务器里（那个只服务 enable_forward_dns 的 LAN 部署）。
//
// 它同时固定 5.4 的两条契约：A 给 overlay 地址、AAAA 给 NOERROR 空应答。上游与
// 直连都没有被碰到（见 newVPNTestServer 的直连拨号器会直接报错）。
func TestDNSInterceptorAnswersPeerNamesLocally(t *testing.T) {
	srv := newVPNTestServer(t, staticTestVPN("b.", netip.MustParseAddr("198.19.0.15")), nil)

	for _, tc := range []struct {
		name      string
		qtype     uint16
		wantIP    string
		wantEmpty bool
	}{
		{name: "A returns the overlay address", qtype: dns.TypeA, wantIP: "198.19.0.15"},
		{name: "AAAA is an empty NOERROR", qtype: dns.TypeAAAA, wantEmpty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := new(dns.Msg)
			query.SetQuestion("b.", tc.qtype)
			query.Id = 0x1234

			plan := srv.dns.plan(query)
			if plan.action != dnsActionStatic {
				t.Fatalf("action = %v, want dnsActionStatic", plan.action)
			}
			if plan.static == nil {
				t.Fatal("a static action must carry the reply")
			}
			plan.static.Id = query.Id

			if plan.static.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[plan.static.Rcode])
			}
			if tc.wantEmpty {
				if len(plan.static.Answer) != 0 {
					t.Fatalf("answers = %d, want 0 (an empty answer, not NXDOMAIN)", len(plan.static.Answer))
				}
				return
			}
			if len(plan.static.Answer) != 1 {
				t.Fatalf("answers = %d, want 1", len(plan.static.Answer))
			}
			a, ok := plan.static.Answer[0].(*dns.A)
			if !ok {
				t.Fatalf("answer type = %T, want *dns.A", plan.static.Answer[0])
			}
			if got := a.A.String(); got != tc.wantIP {
				t.Errorf("A = %s, want %s", got, tc.wantIP)
			}
			if a.Hdr.Ttl == 0 {
				t.Error("the static answer must carry the shared static TTL")
			}
		})
	}
}

// TestDNSStaticAnswerSurvivesTheUDPFrontend 固定前端真的会把这个动作写回去：
// plan 层返回了应答而前端漏掉分支的话，用户看到的是"解析超时"。
func TestDNSStaticAnswerSurvivesTheUDPFrontend(t *testing.T) {
	srv := newVPNTestServer(t, staticTestVPN("b.", netip.MustParseAddr("198.19.0.15")), nil)

	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp socket: %v", err)
	}
	t.Cleanup(func() { sock.Close() }) //nolint:errcheck
	clientAddr := sock.LocalAddr().(*net.UDPAddr)

	query := new(dns.Msg)
	query.SetQuestion("b.", dns.TypeA)
	query.Id = 0x2468
	data, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	// 目标解析器只是"客户端请求的地址"，静态分支不会拨它；这里用一个必然不可达
	// 的地址来强调这一点。
	const requested = "127.0.0.1:1"
	frame, _ := buildUDPFrame(t, requested, data)
	if err := srv.handleDNS(srv.registerTestUDPRelay(sock, clientAddr), frame, query, data); err != nil {
		t.Fatalf("handleDNS: %v", err)
	}

	if err := sock.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := sock.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read udp reply: %v", err)
	}
	gotTarget, gotData := parseUDPFrame(t, buf[:n])
	if gotTarget != requested {
		t.Errorf("reply source = %s, want the client's target %s", gotTarget, requested)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(gotData); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	if resp.Id != query.Id {
		t.Errorf("response id = %#x, want %#x", resp.Id, query.Id)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", resp.Answer[0])
	}
	if got := a.A.String(); got != "198.19.0.15" {
		t.Errorf("A = %s, want 198.19.0.15", got)
	}
}

// TestDNSStaticAnswerSurvivesTheTCPFrontend 固定 TCP DNS 前端的分支：系统解析器
// 在 UDP 被截断时会改用 TCP，两条前端必须给出同一份应答（plan 是共用的，前端各自
// 的 switch 分支不是）。
func TestDNSStaticAnswerSurvivesTheTCPFrontend(t *testing.T) {
	srv := newVPNTestServer(t, staticTestVPN("b.", netip.MustParseAddr("198.19.0.15")), nil)

	client, br := serveTCPDNSHandler(t, srv, "127.0.0.1:1")
	awaitSocks5Reply(t, client, br)

	query := new(dns.Msg)
	query.SetQuestion("b.", dns.TypeA)
	query.Id = 0x1357
	if err := writeTCPDNSMessage(client, query); err != nil {
		t.Fatalf("write query: %v", err)
	}

	resp, err := readTCPDNSMessage(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Id != query.Id {
		t.Errorf("response id = %#x, want %#x", resp.Id, query.Id)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", resp.Answer[0])
	}
	if got := a.A.String(); got != "198.19.0.15" {
		t.Errorf("A = %s, want 198.19.0.15", got)
	}
}

// TestDNSInterceptorLeavesOtherNamesAndTypesAlone 固定钩子的边界：非对端名与其他
// qtype 都必须回到原有分流路径（这里断言动作不是 dnsActionStatic，具体的转发行为
// 由既有的 DNS 用例覆盖）。
func TestDNSInterceptorLeavesOtherNamesAndTypesAlone(t *testing.T) {
	srv := newVPNTestServer(t, staticTestVPN("b.", netip.MustParseAddr("198.19.0.15")), nil)

	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{"example.com.", dns.TypeA}, // 非对端名
		{"b.", dns.TypeTXT},         // 对端名，但不是 A/AAAA
	} {
		query := new(dns.Msg)
		query.SetQuestion(tc.name, tc.qtype)
		if plan := srv.dns.plan(query); plan.action == dnsActionStatic {
			t.Errorf("%s/%s was answered locally", tc.name, dns.TypeToString[tc.qtype])
		}
	}
}

// TestVPNStaticNamesIsOptional 固定可选能力的边界：没有 ResolveStatic 的注入面
// （或没有注入）不会提供静态应答。
func TestVPNStaticNamesIsOptional(t *testing.T) {
	if got := vpnStaticNames(staticTestVPN("b.", netip.MustParseAddr("198.19.0.15"))); got == nil {
		t.Error("a route implementing ResolveStatic must be picked up as the static resolver")
	}
	if got := vpnStaticNames(vpnDialOnlyRoute{}); got != nil {
		t.Errorf("a route without ResolveStatic must not provide static answers, got %T", got)
	}
	if got := vpnStaticNames(nil); got != nil {
		t.Errorf("a nil injection must not provide static answers, got %T", got)
	}
}
