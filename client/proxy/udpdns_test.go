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
)

// startUDPDNSResponderAny 启动一个本地 UDP DNS 应答器：无论 qtype 一律回一条 A
// 记录。用于验证 UDP 拦截对非 A/AAAA 查询也同样生效。
func startUDPDNSResponderAny(t *testing.T, answerIP string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp responder: %v", err)
	}
	t.Cleanup(func() { pc.Close() }) //nolint:errcheck
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(answerIP),
			})
			data, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(data, addr)
		}
	}()
	return pc.LocalAddr().String()
}

// newUDPDNSTestServer 构造一个可用于 UDP DNS 拦截测试的 Socks5Server，并返回一个
// 同时充当客户端来源地址与 SOCKS5 UDPConn 的 socket（应答会发回查询来源地址，
// 因此可直接读回断言），以及记录每次直连拨号地址的通道。
func newUDPDNSTestServer(t *testing.T, rt *router.Router) (*Socks5Server, *net.UDPConn, chan string) {
	t.Helper()
	// 单个 UDP socket 同时充当"客户端来源地址"和 SOCKS5 服务器的 UDPConn：应答
	// 会被发回查询的来源地址，因此可以直接从这个 socket 读回来断言。
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp socket: %v", err)
	}
	t.Cleanup(func() { sock.Close() }) //nolint:errcheck

	// 候选列表是 [请求的解析器, 内置列表...] 并发竞争，因此只统计请求地址是否
	// 被拨到；内置地址同时拨出属于设计内的兜底，不是错误。
	dialed := make(chan string, 8)
	srv := newDirectUDPTestServer(t, func(_ context.Context, network, addr string) (net.Conn, error) {
		select {
		case dialed <- addr:
		default:
		}
		var d net.Dialer
		return d.Dial(network, addr)
	})
	// 拦截器在构造时持有 router 指针：测试直接注入的两个使用方必须同时更新。
	srv.router, srv.dns.router = rt, rt
	// 把这个 socket 注册为当前 UDP 中继：应答（sendToClient/responseDNSMsg）会
	// 经它写回查询的来源地址，因此可以直接从这里读回断言。
	srv.registerTestUDPRelay(sock, sock.LocalAddr().(*net.UDPAddr))
	return srv, sock, dialed
}

// TestHandleUDPInterceptsNonAddressQtype 覆盖 UDP/TCP 判定统一后的行为：MX/TXT/
// HTTPS 等非 A/AAAA 查询过去会因为 util.IsDNSRequest 只认 A/AAAA 而落入普通 UDP
// 分流（按目标 IP 直连出网），现在必须同样按查询域名走 DNS 拦截。用例同时验证
// 直连分支拨的是客户端请求的解析器地址，而不是内置列表。
func TestHandleUDPInterceptsNonAddressQtype(t *testing.T) {
	easydns.ResetResolveState()
	responder := startUDPDNSResponderAny(t, "1.2.3.4")
	// 内置列表指向必然拨不通的地址：只有真正采用"客户端请求的解析器"才能拿到应答。
	oldDNS := clientconfig.DirectDNSServers
	clientconfig.DirectDNSServers = []string{"127.0.0.1:1"}
	t.Cleanup(func() { clientconfig.DirectDNSServers = oldDNS })

	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	rt.AddDirectDomain("direct.example.com")

	srv, sock, dialed := newUDPDNSTestServer(t, rt)
	clientAddr := sock.LocalAddr().(*net.UDPAddr)

	query := new(dns.Msg)
	query.SetQuestion("direct.example.com.", dns.TypeMX)
	query.Id = 0x4321
	data, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	// 客户端显式请求的解析器就是本地应答器本身：它必须被真正拨到。
	//
	// 这里走 handleDNS 而不是 handleUDP：handleUDP 只把 53 端口的数据报交给 DNS
	// 拦截，而本用例要验证"客户端请求的解析器被真正拨到"，需要应答器监听一个可绑定的
	// 高位端口（CI 上无法绑定 53）。入口门控本身由
	// TestHandleUDPDNSInterceptionRequiresPort53 与 TestHandleUDPDropsLinkLocalTargets 覆盖。
	requested := responder
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
	if resp.Id != 0x4321 {
		t.Errorf("response id = %#x, want 0x4321", resp.Id)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Errorf("answers = %d, want 1 (MX query must be intercepted, not relayed as plain UDP)", len(resp.Answer))
	}

	// 请求的解析器必须真的被拨到：内置列表在这里是拨不通的 127.0.0.1:1，因此拿到
	// 应答只能来自 requested。
	var sawRequested bool
	for {
		select {
		case addr := <-dialed:
			if addr == requested {
				sawRequested = true
			}
			continue
		default:
		}
		break
	}
	if !sawRequested {
		t.Errorf("requested resolver %s was never dialed", requested)
	}
}

// TestProxyDNSQueriesShareOneTunnelExchange 固定"客户端把一个 socket 上的所有查询
// 复用到同一条隧道流"这一既有行为——它是服务端"同一条 UDP 会话里可能看到不同域名"
// 的前提，也是"路由中途变化需要重绑上游"的由来。
//
// 键是「客户端数据报来源地址 + 上游」，与域名无关：来自同一 socket 的两个不同域名
// 查询因此落在同一个交换上（传输层只开一条流），服务端只看到一条 UDP 会话。
func TestProxyDNSQueriesShareOneTunnelExchange(t *testing.T) {
	// 内置直连列表指向拨不通的地址：这一条用例里第二个域名必须走代理分支，
	// 而不是被判定为直连后在本地解析。
	oldDNS := clientconfig.DirectDNSServers
	clientconfig.DirectDNSServers = []string{"127.0.0.1:1"}
	t.Cleanup(func() { clientconfig.DirectDNSServers = oldDNS })

	// proxy_rule=proxy：客户端规则把两个域名都判为走代理，隔离掉 GeoIP 的影响。
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleProxy, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	srv, sock, _ := newUDPDNSTestServer(t, rt)

	// 第一条查询创建交换，第二条必须复用它（键里没有域名）。
	if err := srv.dns.proxyUDPQuery(sock.LocalAddr().(*net.UDPAddr), udpDNSQuery{
		raw:   mustPackDNSQuery(t, "mtalk.google.com"),
		src:   sock.LocalAddr().String(),
		dst:   clientconfig.ProxyDNSServer,
		reply: udpReply{msg: func(*dns.Msg) error { return nil }, raw: func([]byte) {}},
	}, dnsPlan{action: dnsActionProxy, domain: "mtalk.google.com", qtype: "A"}); err != nil {
		t.Fatalf("first proxyUDPQuery: %v", err)
	}
	key := sock.LocalAddr().String() + "_" + clientconfig.ProxyDNSServer
	first, ok := srv.udp.exchangeFor(key)
	if !ok {
		t.Fatalf("no exchange after the first query (key %q)", key)
	}

	if err := srv.dns.proxyUDPQuery(sock.LocalAddr().(*net.UDPAddr), udpDNSQuery{
		raw:   mustPackDNSQuery(t, "www.example.com"),
		src:   sock.LocalAddr().String(),
		dst:   clientconfig.ProxyDNSServer,
		reply: udpReply{msg: func(*dns.Msg) error { return nil }, raw: func([]byte) {}},
	}, dnsPlan{action: dnsActionProxy, domain: "www.example.com", qtype: "A"}); err != nil {
		t.Fatalf("second proxyUDPQuery: %v", err)
	}
	second, ok := srv.udp.exchangeFor(key)
	if !ok {
		t.Fatal("the exchange disappeared between queries")
	}
	if first != second {
		t.Fatal("a second domain must reuse the same exchange, not open another stream")
	}
}

// TestDirectClassifiedQueryOpensNoTunnelExchange 补全上面那条的另一半：被判定为
// **直连**的域名根本不建立隧道交换（它在本地解析），因此服务端会话里出现的每个
// 域名都属于"走代理"这一支——服务端无法从客户端行为预判它的 next_proxy 规则会不会命中。
func TestDirectClassifiedQueryOpensNoTunnelExchange(t *testing.T) {
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	rt.AddDirectDomain("direct.example.com")
	srv, sock, _ := newUDPDNSTestServer(t, rt)

	// proxy_rule=auto + 显式直连域名：拦截器的分流判定为直连，走本地解析分支。
	query := mustPackDNSQuery(t, "direct.example.com")
	msg := mustUnpackDNS(t, query)
	if action := srv.dns.plan(msg).action; action != dnsActionDirect {
		t.Fatalf("plan action = %v, want dnsActionDirect", action)
	}
	// 直连解析在这一步真的去拨解析器（测试环境必然失败），但它绝不该建立隧道交换——
	// 那正是本用例要断言的事实。
	_ = srv.dns.handleUDPQuery(sock.LocalAddr().(*net.UDPAddr), udpDNSQuery{
		raw:   query,
		msg:   msg,
		src:   sock.LocalAddr().String(),
		dst:   clientconfig.ProxyDNSServer,
		reply: udpReply{msg: func(*dns.Msg) error { return nil }, raw: func([]byte) {}},
	})

	key := sock.LocalAddr().String() + "_" + clientconfig.ProxyDNSServer
	if _, ok := srv.udp.exchangeFor(key); ok {
		t.Fatal("a direct-classified domain must not open a tunnel exchange")
	}
}

// mustPackDNSQuery / mustUnpackDNS 是这两条用例的小工具。
func mustPackDNSQuery(t *testing.T, domain string) []byte {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return raw
}

func mustUnpackDNS(t *testing.T, raw []byte) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	if err := m.Unpack(raw); err != nil {
		t.Fatalf("unpack query: %v", err)
	}
	return m
}
