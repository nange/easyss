package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startLocalDNSServer starts a local UDP DNS server answering AAAA queries
// for "test.local." with ::1 (mirrors client/dns/lookup_test.go).
func startLocalDNSServer(t *testing.T) (string, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // random available port
	require.NoError(t, err)

	server := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			for _, q := range r.Question {
				if q.Qtype == dns.TypeAAAA {
					m.Answer = append(m.Answer, &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						AAAA: net.ParseIP("::1"),
					})
				}
			}
			_ = w.WriteMsg(m)
		}),
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	return pc.LocalAddr().String(), func() {
		_ = server.Shutdown()
	}
}

func TestResolveServerIPV6IPServer(t *testing.T) {
	cfg := &config.ClientConfig{
		Servers: []*config.ServerProfile{{Address: "2001:db8::1", Default: true}},
	}
	assert.Equal(t, "2001:db8::1", resolveServerIPV6(context.Background(), cfg))

	cfg = &config.ClientConfig{
		Servers: []*config.ServerProfile{{Address: "1.2.3.4", Default: true}},
	}
	assert.Equal(t, "", resolveServerIPV6(context.Background(), cfg))
}

func TestResolveServerIPV6BoundedByContext(t *testing.T) {
	// A blackhole direct DNS server makes every lookup fail; the context
	// deadline must bound the whole resolution instead of the per-query 5s
	// timeout stalling startup.
	old := config.DirectDNSServers
	config.DirectDNSServers = []string{"127.0.0.1:1"}
	defer func() { config.DirectDNSServers = old }()
	easydns.MarkBuiltinDNSAvailable()

	cfg := &config.ClientConfig{
		Servers: []*config.ServerProfile{{Address: "proxy.example.com", Default: true}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	got := resolveServerIPV6(ctx, cfg)
	assert.Equal(t, "", got)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestResolveServerIPV6WithLocalDNS(t *testing.T) {
	addr, shutdown := startLocalDNSServer(t)
	defer shutdown()

	old := config.DirectDNSServers
	config.DirectDNSServers = []string{addr}
	defer func() { config.DirectDNSServers = old }()
	easydns.MarkBuiltinDNSAvailable()

	cfg := &config.ClientConfig{
		Servers: []*config.ServerProfile{{Address: "test.local", Default: true}},
	}
	got := resolveServerIPV6(context.Background(), cfg)
	assert.Equal(t, net.ParseIP("::1").String(), got)
}
