package proxy

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/txthinking/socks5"
)

// nbnsQName 把 NetBIOS 名字编码成 NBNS 查询里的 QNAME：15 字节名字（空格补齐）
// + 1 字节后缀，每个字节拆成两个 'A'+半字节 的字符，共 32 个字符。
func nbnsQName(name string, suffix byte) string {
	raw := [16]byte{}
	for i := range raw {
		raw[i] = ' '
	}
	copy(raw[:], strings.ToUpper(name))
	raw[15] = suffix

	out := make([]byte, 0, 32)
	for _, b := range raw {
		out = append(out, 'A'+(b>>4), 'A'+(b&0x0f))
	}
	return string(out)
}

// nbnsQueryPayload 组一条 NBNS 名字查询报文（真实世界里发往 UDP 137）：DNS 线格式的
// 头部 + NetBIOS first-level 编码的 QNAME + QTYPE=0x0020(NB) + QCLASS=0x0001(IN)。
// 在 DNS 类型表里 QTYPE 32 是 NIMLOC——这正是日志里出现 qtype=NIMLOC 的原因。
func nbnsQueryPayload(name string, suffix byte) []byte {
	qname := nbnsQName(name, suffix)
	data := []byte{0x12, 0x34, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, byte(len(qname))}
	data = append(data, qname...)
	return append(data, 0x00, 0x00, 0x20, 0x00, 0x01)
}

// newUDPTargetTestServer 构造一个用于 UDP 入口判定的 Socks5Server：返回的 socket
// 同时充当客户端来源地址与 SOCKS5 UDPConn，以及记录直连拨号地址的通道。
//
// 直连拨号被替换为"记录目标后拨到本机静默对端"：用例只关心某条数据报有没有被拨到，
// 既不希望（255.255.255.255/198.18.255.255 这类目标在本机会被路由进 TUN，真的发出去）
// 也不依赖本机路由表能否连上目标。
func newUDPTargetTestServer(t *testing.T, rt *router.Router) (*Socks5Server, *net.UDPConn, chan string) {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp socket: %v", err)
	}
	t.Cleanup(func() { sock.Close() }) //nolint:errcheck

	silent := startSilentRemoteUDP(t)
	dialed := make(chan string, 8)
	srv := newDirectUDPTestServer(t, func(_ context.Context, network, addr string) (net.Conn, error) {
		select {
		case dialed <- addr:
		default:
		}
		var d net.Dialer
		return d.Dial(network, silent)
	})
	// 拦截器在构造时持有 router 指针：两个使用方必须同时更新。
	srv.router, srv.dns.router = rt, rt
	return srv, sock, dialed
}

func newUDPTargetRouter(t *testing.T) *router.Router {
	t.Helper()
	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	return rt
}

// TestHandleUDPDNSInterceptionRequiresPort53 覆盖 UDP DNS 拦截的端口门控：NBNS(137)
// 这类"长得像 DNS"的链路本地协议必须回落到普通 UDP 分流，不能再被 DNS 拦截送进隧道。
// 载荷与目的地取自真实日志：主机 NANGE 的 file server service 名，发往 TUN 子网广播。
func TestHandleUDPDNSInterceptionRequiresPort53(t *testing.T) {
	const target = "198.18.255.255:137"
	payload := nbnsQueryPayload("NANGE", 0x20)

	// 前提校验：这条载荷确实会被当成 DNS 查询解包，否则本用例证明不了门控。
	probe := new(dns.Msg)
	if err := probe.Unpack(payload); err != nil {
		t.Fatalf("unpack nbns payload: %v", err)
	}
	if !isDNSQueryMsg(probe) {
		t.Fatal("nbns payload must parse as a dns query, otherwise this case proves nothing")
	}
	if got := dns.TypeToString[probe.Question[0].Qtype]; got != "NIMLOC" {
		t.Fatalf("qtype = %s, want NIMLOC (QTYPE 32)", got)
	}
	if got := probe.Question[0].Name; got != nbnsQName("NANGE", 0x20)+"." {
		t.Fatalf("qname = %q, want the NetBIOS first-level encoded name", got)
	}

	srv, sock, dialed := newUDPTargetTestServer(t, newUDPTargetRouter(t))
	clientAddr := sock.LocalAddr().(*net.UDPAddr)

	if err := srv.handleUDP(&socks5.Server{UDPConn: sock}, clientAddr, buildUDPDatagram(t, target, payload)); err != nil {
		t.Fatalf("handleUDP: %v", err)
	}

	// 198.18.255.255 属于 LAN（198.18.0.0/15）→ 普通 UDP 分流判直连，直连拨号必然
	// 发生（拨号在 handleUDP 返回前同步完成）。若这条查询仍被 DNS 拦截，它走的是
	// proxy 分支，不会有任何直连拨号。
	select {
	case addr := <-dialed:
		if addr != target {
			t.Errorf("direct dial = %s, want %s", addr, target)
		}
	default:
		t.Error("nbns query on port 137 was not relayed as plain UDP (no direct dial happened)")
	}
}

// TestHandleUDPDNSInterceptionOnPort53 是端口门控的阳性对照：发往 53 端口的 DNS
// 查询必须继续进入 DNS 拦截——被屏蔽域名会同步收到本地应答，且不落到普通 UDP 直连中继。
// 屏蔽域名取自 geosite 屏蔽列表（与 TestHandleTCPDNSBlock 同一个域名）。
func TestHandleUDPDNSInterceptionOnPort53(t *testing.T) {
	const target = "223.5.5.5:53"

	q := new(dns.Msg)
	q.SetQuestion("adsensecamp.com.", dns.TypeA)
	q.Id = 0x2222
	data, err := q.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}

	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAutoBlock, IPV6Rule: router.IPV6RuleDisable})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	srv, sock, dialed := newUDPTargetTestServer(t, rt)
	clientAddr := sock.LocalAddr().(*net.UDPAddr)

	if err := srv.handleUDP(&socks5.Server{UDPConn: sock}, clientAddr, buildUDPDatagram(t, target, data)); err != nil {
		t.Fatalf("handleUDP: %v", err)
	}

	if err := sock.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := sock.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read udp reply: %v (a dns query on port 53 must still be intercepted)", err)
	}
	reply, err := socks5.NewDatagramFromBytes(buf[:n])
	if err != nil {
		t.Fatalf("parse datagram: %v", err)
	}
	if got := reply.Address(); got != target {
		t.Errorf("reply source = %s, want the client's target %s", got, target)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(reply.Data); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	if !resp.Response || resp.Id != q.Id {
		t.Errorf("reply response=%v id=%#x, want a blocked answer with id %#x", resp.Response, resp.Id, q.Id)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("answers = %v, want none (blocked domain)", resp.Answer)
	}

	select {
	case addr := <-dialed:
		t.Errorf("dns query on port 53 must not be relayed as plain UDP, but it was dialed (%s)", addr)
	default:
	}
}

// TestHandleUDPDropsLinkLocalTargets 覆盖链路本地目的地的丢弃：受限广播/多播/
// 链路本地单播既不中继（应答收不到，且未绑定物理接口的直连拨号会把报文送回 TUN，
// 形成 代理→直连→TUN→代理 的环路），也不走 DNS 拦截、不产生任何应答。
func TestHandleUDPDropsLinkLocalTargets(t *testing.T) {
	tests := []struct {
		name   string
		target string
		// isQuery 表示载荷是 DNS 查询：mDNS/LLMNR 就是这样——5353/5355 上的 DNS 查询。
		isQuery bool
	}{
		{"limited broadcast nbns", "255.255.255.255:137", false},
		{"limited broadcast dns", "255.255.255.255:53", true},
		{"mDNS multicast query", "224.0.0.251:5353", true},
		{"LLMNR multicast query", "224.0.0.252:5355", true},
		{"SSDP multicast", "239.255.255.250:1900", false},
		{"link-local unicast", "169.254.10.20:137", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := []byte{0xde, 0xad, 0xbe, 0xef}
			if tt.isQuery {
				q := new(dns.Msg)
				q.SetQuestion("printer.local.", dns.TypeA)
				data, err := q.Pack()
				if err != nil {
					t.Fatalf("pack query: %v", err)
				}
				payload = data
			}

			srv, sock, dialed := newUDPTargetTestServer(t, newUDPTargetRouter(t))
			clientAddr := sock.LocalAddr().(*net.UDPAddr)

			if err := srv.handleUDP(&socks5.Server{UDPConn: sock}, clientAddr, buildUDPDatagram(t, tt.target, payload)); err != nil {
				t.Fatalf("handleUDP: %v", err)
			}

			select {
			case addr := <-dialed:
				t.Errorf("target %s must be dropped, but it was dialed (%s)", tt.target, addr)
			default:
			}

			// 也不能有任何应答写回客户端（DNS 拦截会同步写回应答）。
			if err := sock.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			buf := make([]byte, 2048)
			if n, _, err := sock.ReadFromUDP(buf); err == nil {
				t.Errorf("target %s must be dropped, but %d bytes were written back", tt.target, n)
			}
		})
	}
}

// TestIsNonRelayableUDPTarget 固定判定的边界：只丢弃受限广播/多播/链路本地单播，
// 子网广播（198.18.255.255、192.168.1.255）是 global unicast，直连拨号会绑定物理
// 接口，历史上一直按直连中继，行为必须保持不变。
func TestIsNonRelayableUDPTarget(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"255.255.255.255", true}, // 受限广播
		{"224.0.0.251", true},     // mDNS
		{"239.255.255.250", true}, // SSDP
		{"169.254.1.1", true},     // IPv4 链路本地
		{"ff02::fb", true},        // IPv6 多播
		{"fe80::1", true},         // IPv6 链路本地
		{"198.18.255.255", false}, // TUN 子网广播
		{"192.168.1.255", false},  // LAN 子网广播
		{"255.255.255.254", false},
		{"8.8.8.8", false},
		{"2001:4860:4860::8888", false},
		{"2606:4700::1111", false},
		{"example.com", false}, // 域名不在此判定
		{"", false},
	}
	for _, tt := range tests {
		if got := isNonRelayableUDPTarget(tt.host); got != tt.want {
			t.Errorf("isNonRelayableUDPTarget(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}
