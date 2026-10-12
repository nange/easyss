package dns

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/nange/easyss/v3/stats"
)

// staticNames 是一个固定表驱动的 StaticNames 实现。
type staticNames map[string]netip.Addr

func (s staticNames) ResolveStatic(name string) (netip.Addr, bool) {
	addr, ok := s[name]
	return addr, ok
}

// captureWriter 记录处理器写回的报文，供直接调用 handleDNS 的用例断言。
type captureWriter struct {
	msg *dns.Msg
}

func (w *captureWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (w *captureWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}
func (w *captureWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *captureWriter) Write([]byte) (int, error) { return 0, nil }
func (w *captureWriter) Close() error              { return nil }
func (w *captureWriter) TsigStatus() error         { return nil }
func (w *captureWriter) TsigTimersOnly(bool)       {}
func (w *captureWriter) Hijack()                   {}

// TestStaticNameAnswersAWithoutUpstream 固定 A 查询的两条性质：就地应答，且
// **不碰上游**——上游被设成不可达地址，一旦发生转发就会得到 SERVFAIL。
func TestStaticNameAnswersAWithoutUpstream(t *testing.T) {
	fs := NewForwardServer("127.0.0.1:0", false, staticNames{
		"b.": netip.MustParseAddr("198.19.0.15"),
	})
	fs.dnsServers = []string{"127.0.0.1:1"}

	req := new(dns.Msg)
	req.SetQuestion("b.", dns.TypeA)

	before := stats.Collect()
	w := &captureWriter{}
	fs.handleDNS(w, req)
	// 统计触点：A 与 AAAA 两条契约都是"本地静态应答"，都必须被计到（见
	// stats.RecordVPNDNSStaticAnswer）。
	if after := stats.Collect(); after.VPNDNSStaticAnswers != before.VPNDNSStaticAnswers+1 {
		t.Errorf("vpn_dns_static_answers = %d, want %d: a locally answered peer name must be counted",
			after.VPNDNSStaticAnswers, before.VPNDNSStaticAnswers+1)
	}

	if w.msg == nil {
		t.Fatal("no reply written")
	}
	if w.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[w.msg.Rcode])
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(w.msg.Answer))
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", w.msg.Answer[0])
	}
	if got := a.A.String(); got != "198.19.0.15" {
		t.Errorf("A = %s, want 198.19.0.15", got)
	}
	if a.Hdr.Ttl != StaticNameTTL {
		t.Errorf("ttl = %d, want %d", a.Hdr.Ttl, StaticNameTTL)
	}
}

// TestStaticNameAnswersEmptyAAAA 固定 5.4 的 AAAA 契约：NOERROR 且无记录
// （不是 NXDOMAIN），使客户端立刻回退到 A 记录。
func TestStaticNameAnswersEmptyAAAA(t *testing.T) {
	fs := NewForwardServer("127.0.0.1:0", false, staticNames{
		"b.": netip.MustParseAddr("198.19.0.15"),
	})
	fs.dnsServers = []string{"127.0.0.1:1"}

	req := new(dns.Msg)
	req.SetQuestion("b.", dns.TypeAAAA)

	w := &captureWriter{}
	fs.handleDNS(w, req)

	if w.msg == nil {
		t.Fatal("no reply written")
	}
	if w.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR (an empty answer, not NXDOMAIN)", dns.RcodeToString[w.msg.Rcode])
	}
	if len(w.msg.Answer) != 0 {
		t.Fatalf("answers = %d, want 0", len(w.msg.Answer))
	}
}

// TestStaticNameLeavesOtherNamesAndTypesAlone 验证钩子的边界：非静态名与其他
// 查询类型都必须原样走既有转发路径（这里用一个真实的上游来证明它确实被转发）。
func TestStaticNameLeavesOtherNamesAndTypesAlone(t *testing.T) {
	upstream := startTestDNSServer(t, false)
	fs := NewForwardServer("127.0.0.1:0", false, staticNames{
		"b.": netip.MustParseAddr("198.19.0.15"),
	})
	fs.dnsServers = []string{upstream}

	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{"example.com.", dns.TypeA}, // 非对端名
		{"b.", dns.TypeTXT},         // 对端名，但不是 A/AAAA
	} {
		req := new(dns.Msg)
		req.SetQuestion(tc.name, tc.qtype)

		w := &captureWriter{}
		fs.handleDNS(w, req)

		if w.msg == nil {
			t.Fatalf("%s/%s: no reply written", tc.name, dns.TypeToString[tc.qtype])
		}
		if w.msg.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s/%s: rcode = %s, want the upstream NOERROR",
				tc.name, dns.TypeToString[tc.qtype], dns.RcodeToString[w.msg.Rcode])
		}
	}
}

// TestNoStaticNamesKeepsForwarding 验证 nil 钩子下行为不变：任何名字都转发，
// 且没有任何本地应答。
func TestNoStaticNamesKeepsForwarding(t *testing.T) {
	upstream := startTestDNSServer(t, false)
	fs := NewForwardServer("127.0.0.1:0", false, nil)
	fs.dnsServers = []string{upstream}

	req := new(dns.Msg)
	req.SetQuestion("b.", dns.TypeA)

	w := &captureWriter{}
	fs.handleDNS(w, req)

	if w.msg == nil {
		t.Fatal("no reply written")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("answers = %d, want the upstream's single A record", len(w.msg.Answer))
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type = %T, want *dns.A", w.msg.Answer[0])
	}
	if a.A.String() != "1.2.3.4" {
		t.Errorf("A = %s, want the upstream answer 1.2.3.4", a.A.String())
	}
}
