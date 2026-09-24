package dns

import (
	"net"
	"slices"
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
// 上游。若没有该过滤，回退会递归进自身，堆积 goroutine 和 UDP socket，直到
// 单次查询超时解开这条链。
//
// 构造必须用生产监听地址（":53"）：过滤条件曾经是 listenAddr 的字符串相等，
// 于是改用通配地址后它永不命中——而 SystemDNSServers 的条目一律是 host:port，
// 永远不可能等于 ":53"。用 127.0.0.1:53 构造的测试会"通过但空转"，掩盖该回归。
func TestForwardQuerySkipsSelfAsUpstream(t *testing.T) {
	old := systemDNSServersFunc
	systemDNSServersFunc = func() []string {
		// 路由器上 /etc/resolv.conf 的常见形态：回环（dnsmasq 惯例）与
		// 本机网卡地址，外加一个不可达的额外服务器。
		return []string{"127.0.0.1:53", "[::1]:53", localIPv4(t) + ":53", "127.0.0.1:1"}
	}
	t.Cleanup(func() {
		systemDNSServersFunc = old
		resetSystemDNSCache()
		resetBuiltinDNSCircuit()
	})

	fs := NewForwardServer(":53", false)
	fs.client = &dns.Client{Timeout: 200 * time.Millisecond}
	fs.dnsServers = []string{"127.0.0.1:1"} // 内置服务器全部不可达

	got := fs.systemDNSServers()
	want := []string{"127.0.0.1:1"}
	if !slices.Equal(got, want) {
		t.Fatalf("systemDNSServers = %v, want only the non-self server %v", got, want)
	}

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	if _, err := fs.forwardQuery(msg); err == nil {
		t.Fatal("expected error: both the builtin and the non-self fallback server are unreachable")
	}
}

// localIPv4 返回本机一个非环回 IPv4 地址，供"本机网卡地址必须被当作自环"的
// 用例使用。没有可用网卡的构建环境跳过该用例。
func localIPv4(t *testing.T) string {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("list interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			return ipnet.IP.To4().String()
		}
	}
	t.Skip("no non-loopback ipv4 address available")
	return ""
}

// TestIsSelfUpstreamAddr 覆盖自环判定的各条规则：环回/未指定/多播恒为自环，
// 非本机地址不是，本机网卡地址只在端口相同时才算自环（另一端口上的本机解析器
// 并不会打回自己）。
func TestIsSelfUpstreamAddr(t *testing.T) {
	tests := []struct {
		name       string
		addr       string
		listenAddr string
		want       bool
	}{
		{"loopback same port", "127.0.0.1:53", ":53", true},
		{"loopback v6 same port", "[::1]:53", ":53", true},
		{"unspecified is self when listening wildcard", "0.0.0.0:53", ":53", true},
		{"unspecified v6 is self when listening wildcard", "[::]:53", ":53", true},
		{"public dns is not self", "8.8.8.8:53", ":53", false},
		{"bare loopback without port", "127.0.0.1", ":53", true},
		{"hostname upstream is not judged", "dns.example.com:53", ":53", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSelfUpstreamAddr(tt.addr, tt.listenAddr); got != tt.want {
				t.Errorf("isSelfUpstreamAddr(%q, %q) = %v, want %v", tt.addr, tt.listenAddr, got, tt.want)
			}
		})
	}

	// 本机网卡地址：仅当端口等于监听端口时才算自环。
	local := localIPv4(t)
	if !isSelfUpstreamAddr(local+":53", ":53") {
		t.Errorf("isSelfUpstreamAddr(%q:53, \":53\") = false, want true (a local interface address on the listen port reaches ourselves)", local)
	}
	if isSelfUpstreamAddr(local+":5353", ":53") {
		t.Errorf("isSelfUpstreamAddr(%q:5353, \":53\") = true, want false (another port on this host is not our listener)", local)
	}

	// 监听具体地址时，同一端口上的其他本机地址并不会经过本监听 socket
	// （只有绑定的那个地址会），但环回仍然会经过通配之外的自身。
	if !isSelfUpstreamAddr("127.0.0.1:53", "127.0.0.1:53") {
		t.Error("isSelfUpstreamAddr(127.0.0.1:53, 127.0.0.1:53) = false, want true")
	}
}
