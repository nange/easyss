package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startLocalDNSServer starts a local UDP DNS server that responds to A queries for "test.local."
// with a fixed IPv4 address. Returns the server address (ip:port) and a shutdown function.
func startLocalDNSServer(t *testing.T) (string, func()) {
	t.Helper()

	server := &dns.Server{
		Net:  "udp",
		Addr: "127.0.0.1:0", // random available port
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)

			for _, q := range r.Question {
				switch q.Qtype {
				case dns.TypeA:
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    60,
						},
						A: net.IPv4(10, 0, 0, 1),
					})
				case dns.TypeAAAA:
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

	// Start the server in a goroutine.
	go func() {
		_ = server.ListenAndServe()
	}()

	// Wait for the server to be ready.
	time.Sleep(50 * time.Millisecond)

	addr := server.PacketConn.LocalAddr().String()
	return addr, func() {
		_ = server.Shutdown()
	}
}

func TestLookupIPV4From(t *testing.T) {
	addr, shutdown := startLocalDNSServer(t)
	defer shutdown()

	ips, err := LookupIPV4From(addr, "test.local")
	require.NoError(t, err)
	assert.Greater(t, len(ips), 0)
	assert.Equal(t, net.IPv4(10, 0, 0, 1).String(), ips[0].String())
}

func TestLookupIPV6From(t *testing.T) {
	addr, shutdown := startLocalDNSServer(t)
	defer shutdown()

	ips, err := LookupIPV6From(addr, "test.local")
	require.NoError(t, err)
	assert.Greater(t, len(ips), 0)
	assert.Equal(t, net.ParseIP("::1").String(), ips[0].String())
}
