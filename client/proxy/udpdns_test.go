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
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/transport"
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

// TestHandleUDPInterceptsNonAddressQtype 守住 MX/TXT/HTTPS 等非 A/AAAA 查询同样按查询
// 域名走 DNS 拦截，而不是落入普通 UDP 分流按目标 IP 直连出网。
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
	// 这里走 handleDNS 而不是 handleUDP：handleUDP 只把 53 端口的数据报交给 DNS 拦截，
	// 而本用例需要应答器监听可绑定的高位端口（CI 上无法绑定 53）。
	requested := responder
	frame, _ := buildUDPFrame(t, requested, data)
	if err := srv.handleDNS(srv.registerTestUDPRelay(sock, clientAddr), frame, query, data, clientAddr, clientAddr.String()); err != nil {
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

// newDNSMultiplexTestServer 的 DNSResp 取生产量级而不是短超时：交换空闲回收是独立机制，
// 短窗口会让"两条查询复用同一个交换"的断言与回收时机赛跑。
func newDNSMultiplexTestServer(t *testing.T) (*Socks5Server, *mockTransport) {
	t.Helper()
	tr := &mockTransport{streams: []transport.Stream{newBlockingStream(), newBlockingStream()}}
	srv, err := NewSocks5Server(Socks5Options{
		ListenAddr: "127.0.0.1:0",
		Handler:    newTestStreamHandler(tr),
		Method:     protocol.MethodAES256GCM,
		Timeouts: config.Timeouts{
			Base:       30 * time.Second,
			Dial:       10 * time.Second,
			StreamIdle: 30 * time.Second,
			DNSResp:    60 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}
	return srv, tr
}

// TestProxyDNSQueriesShareOneTunnelExchange 守住同一个 socket 上的查询（键是来源地址 +
// 上游，与域名无关）只开一条隧道流——这是服务端"一条会话里可能看到不同域名"的前提。
func TestProxyDNSQueriesShareOneTunnelExchange(t *testing.T) {
	// 内置直连列表指向拨不通的地址：第二个域名必须走代理分支，而不是被判为直连后
	// 在本地解析（那不会打开任何流，见下一条用例）。
	oldDNS := clientconfig.DirectDNSServers
	clientconfig.DirectDNSServers = []string{"127.0.0.1:1"}
	t.Cleanup(func() { clientconfig.DirectDNSServers = oldDNS })

	// proxy_rule=proxy：客户端规则把两个域名都判为走代理，隔离掉 GeoIP 的影响。
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleProxy, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	srv, tr := newDNSMultiplexTestServer(t)
	srv.router, srv.dns.router = rt, rt

	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp socket: %v", err)
	}
	t.Cleanup(func() { sock.Close() }) //nolint:errcheck
	clientAddr := sock.LocalAddr().(*net.UDPAddr)

	for _, domain := range []string{"mtalk.google.com", "www.example.com"} {
		msg := mustUnpackDNS(t, mustPackDNSQuery(t, domain))
		if err := srv.dns.handleUDPQuery(clientAddr, udpDNSQuery{
			raw:   mustPackDNSQuery(t, domain),
			msg:   msg,
			src:   clientAddr.String(),
			dst:   clientconfig.ProxyDNSServer,
			reply: udpReply{msg: func(*dns.Msg) error { return nil }, raw: func([]byte) {}},
		}); err != nil {
			t.Fatalf("handleUDPQuery(%s): %v", domain, err)
		}
	}

	tr.mu.Lock()
	opens := tr.openCount
	tr.mu.Unlock()
	if opens != 1 {
		t.Fatalf("transport opens = %d, want 1 (both domains must share one tunnel stream)", opens)
	}
	key := clientAddr.String() + "_" + clientconfig.ProxyDNSServer
	if _, ok := srv.udp.exchangeFor(key); !ok {
		t.Fatalf("the shared exchange must be registered under %q", key)
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

	srv, tr := newDNSMultiplexTestServer(t)
	srv.router, srv.dns.router = rt, rt

	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp socket: %v", err)
	}
	t.Cleanup(func() { sock.Close() }) //nolint:errcheck

	// 直连解析在这一步真的去拨解析器（测试环境必然失败），但它绝不该打开隧道流。
	query := mustPackDNSQuery(t, "direct.example.com")
	_ = srv.dns.handleUDPQuery(sock.LocalAddr().(*net.UDPAddr), udpDNSQuery{
		raw:   query,
		msg:   mustUnpackDNS(t, query),
		src:   sock.LocalAddr().String(),
		dst:   clientconfig.ProxyDNSServer,
		reply: udpReply{msg: func(*dns.Msg) error { return nil }, raw: func([]byte) {}},
	})

	tr.mu.Lock()
	opens := tr.openCount
	tr.mu.Unlock()
	if opens != 0 {
		t.Fatalf("transport opens = %d, want 0 (a direct-classified domain must not open a tunnel stream)", opens)
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
