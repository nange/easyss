package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startTestDNSServer starts a local udp dns server on a random port. When
// fail is true it replies SERVFAIL to every query, otherwise it answers
// A/AAAA records. It returns the server address and registers cleanup.
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
	// an unreachable local address forces the fallback path
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

// TestForwardQuerySkipsSelfAsUpstream verifies the forward server never uses
// itself as a fallback upstream. During TUN mode the system DNS points at
// 127.0.0.1 (this very server); without the filter the fallback would
// recurse into itself, piling up goroutines and UDP sockets until the
// per-query timeout unwound the chain.
func TestForwardQuerySkipsSelfAsUpstream(t *testing.T) {
	old := systemDNSServersFunc
	systemDNSServersFunc = func() []string {
		// The system DNS in TUN mode: this forward server itself (the
		// real discovery formats it as host:port), plus an unreachable
		// extra.
		return []string{"127.0.0.1:53", "127.0.0.1:1"}
	}
	t.Cleanup(func() {
		systemDNSServersFunc = old
		resetSystemDNSCache()
		resetBuiltinDNSCircuit()
	})

	fs := NewForwardServer("127.0.0.1:53", false)
	fs.client = &dns.Client{Timeout: 200 * time.Millisecond}
	fs.dnsServers = []string{"127.0.0.1:1"} // builtin servers all unreachable

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
