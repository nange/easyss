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
