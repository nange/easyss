package dns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startLocalDNSServer 启动一个本地 UDP DNS 服务器，对 "test.local." 的 A 查询
// 返回固定的 IPv4 地址。返回服务器地址（ip:port）和一个关闭函数。
func startLocalDNSServer(t *testing.T) (string, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // 随机可用端口
	require.NoError(t, err)

	server := &dns.Server{
		PacketConn: pc,
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

	// 在 goroutine 中启动服务器。
	go func() {
		_ = server.ActivateAndServe()
	}()

	addr := pc.LocalAddr().String()
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

// TestLookupIPV6FromContextBounded 验证受 context 约束的变体在 context 截止
// 时间到期时能立即返回，而不是等待单次查询的 5s 超时。
func TestLookupIPV6FromContextBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := LookupIPV6FromContext(ctx, "127.0.0.1:1", "test.local")
	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second)
}
