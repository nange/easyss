package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startTestDNSServer 在随机端口上启动一个本地 UDP DNS 服务器。当 fail 为
// true 时，它对每个查询都回复 SERVFAIL；否则正常应答 A/AAAA 记录。返回
// 服务器地址并注册清理函数。
func startTestDNSServer(t *testing.T, fail bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if fail {
			m.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
				A:   net.ParseIP("1.2.3.4"),
			})
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 600},
				AAAA: net.ParseIP("2001:db8::1"),
			})
		}
		_ = w.WriteMsg(m)
	})}
	go func() {
		_ = srv.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown()
	})
	return pc.LocalAddr().String()
}

// startBlackholeDNSServer 在随机端口上启动一个只收不回的 UDP 服务，模拟
// "黑洞"上游：查询一直不产生应答，客户端只能等到自己的截止时间。被墙的公共
// DNS、或指向不可达网段的错误配置都是这种形态（区别于 SERVFAIL/RST 那种
// 立即失败）。返回地址并注册清理函数。
func startBlackholeDNSServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = pc.Close()
		<-done
	})
	return pc.LocalAddr().String()
}

// startSlowTestDNSServer 启动一个本地 UDP DNS 服务器，对每个查询都延迟 delay
// 后才应答 A/AAAA 记录。用于观察"同一条目的 A 与 AAAA 是否并发"：串行时第二个
// 查询只拿得到剩余预算。
func startSlowTestDNSServer(t *testing.T, delay time.Duration) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(delay)
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
				A:   net.ParseIP("1.2.3.4"),
			})
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 600},
				AAAA: net.ParseIP("2001:db8::1"),
			})
		}
		_ = w.WriteMsg(m)
	})}
	go func() {
		_ = srv.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown()
	})
	return pc.LocalAddr().String()
}

// startTestDNSHandler 在随机端口上启动一个本地 UDP DNS 服务器，把收到的每个
// 查询交给 handler，返回服务器地址并注册清理函数。
func startTestDNSHandler(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() {
		_ = srv.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown()
	})
	return pc.LocalAddr().String()
}

// startCorruptEDNS0DNSServer 复现"OPT 记录被放进 ANSWER 段、真正的记录被挤到
// ADDITIONAL 段"这一类畸形应答（部分家用路由器/缓存对 EDNS0 查询就是这样应答
// 的）。严格解析器（dig/BIND）判为畸形报文，宽松解析器（Go 标准库解析器）只
// 看到一条 41 类型记录、拿不到任何地址，表现为解析失败（见 normalizeEDNS0Answer）。
func startCorruptEDNS0DNSServer(t *testing.T) string {
	t.Helper()
	return startTestDNSHandler(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		m := new(dns.Msg)
		m.SetReply(r)

		opt := new(dns.OPT)
		opt.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}
		m.Answer = append(m.Answer, opt)

		switch q.Qtype {
		case dns.TypeA:
			m.Extra = append(m.Extra, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
				A:   net.ParseIP("1.2.3.4"),
			})
		case dns.TypeAAAA:
			m.Extra = append(m.Extra, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 600},
				AAAA: net.ParseIP("2001:db8::1"),
			})
		}
		_ = w.WriteMsg(m)
	}))
}

// startNODATADNSServer 返回一个对任何查询都回 NOERROR 但没有任何记录的解析器。
func startNODATADNSServer(t *testing.T) string {
	t.Helper()
	return startTestDNSHandler(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	}))
}

func TestForwardQueryFallsBackToSystemDNS(t *testing.T) {
	sysAddr := startTestDNSServer(t, false)
	old := systemDNSServersFunc
	systemDNSServersFunc = func() []string {
		return []string{sysAddr}
	}
	t.Cleanup(func() {
		systemDNSServersFunc = old
		resetSystemDNSCache()
		resetBuiltinDNSCircuit()
	})

	fs := NewForwardServer("127.0.0.1:0", false)
	fs.client = &dns.Client{Timeout: 200 * time.Millisecond}
	// 不可达的本地地址强制走回退路径
	fs.dnsServers = []string{"127.0.0.1:1"}

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	reply, err := fs.forwardQuery(msg)
	if err != nil {
		t.Fatalf("forwardQuery error: %v", err)
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(reply.Answer))
	}
	a, ok := reply.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", reply.Answer[0])
	}
	if a.A.String() != "1.2.3.4" {
		t.Errorf("unexpected answer: %s", a.A.String())
	}
}

func TestForwardQueryAllServersUnavailable(t *testing.T) {
	old := systemDNSServersFunc
	systemDNSServersFunc = func() []string {
		return nil
	}
	t.Cleanup(func() {
		systemDNSServersFunc = old
		resetSystemDNSCache()
		resetBuiltinDNSCircuit()
	})

	fs := NewForwardServer("127.0.0.1:0", false)
	fs.client = &dns.Client{Timeout: 200 * time.Millisecond}
	fs.dnsServers = []string{"127.0.0.1:1"}

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	reply, err := fs.forwardQuery(msg)
	if err == nil {
		t.Fatal("expected error")
	}
	if reply != nil {
		t.Fatalf("expected nil reply, got %v", reply)
	}
}

// TestForwardQuerySkipsSelfAsUpstream 验证转发服务器永远不会把自身作为回退
// 上游。TUN 模式下系统 DNS 指向 127.0.0.1（即本服务器）；若没有该过滤，
// 回退会递归进自身，堆积 goroutine 和 UDP socket，直到单次查询超时解开
// 这条链。
func TestForwardQuerySkipsSelfAsUpstream(t *testing.T) {
	old := systemDNSServersFunc
	systemDNSServersFunc = func() []string {
		// TUN 模式下的系统 DNS：本转发服务器自身（真实发现逻辑会将其格式化
		// 为 host:port），外加一个不可达的额外服务器。
		return []string{"127.0.0.1:53", "127.0.0.1:1"}
	}
	t.Cleanup(func() {
		systemDNSServersFunc = old
		resetSystemDNSCache()
		resetBuiltinDNSCircuit()
	})

	fs := NewForwardServer("127.0.0.1:53", false)
	fs.client = &dns.Client{Timeout: 200 * time.Millisecond}
	fs.dnsServers = []string{"127.0.0.1:1"} // 内置服务器全部不可达

	got := fs.systemDNSServers()
	if len(got) != 1 || got[0] != "127.0.0.1:1" {
		t.Fatalf("systemDNSServers = %v, want only the non-self server [127.0.0.1:1]", got)
	}

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	if _, err := fs.forwardQuery(msg); err == nil {
		t.Fatal("expected error: both the builtin and the non-self fallback server are unreachable")
	}
}
