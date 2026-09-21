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

// TestLookupFromContext 覆盖生产实际使用的受 ctx 约束的查询路径：把查询结果
// 解析成 IP 列表。
func TestLookupFromContext(t *testing.T) {
	addr, shutdown := startLocalDNSServer(t)
	defer shutdown()

	msgA, err := DNSMsgTypeAContext(context.Background(), addr, "test.local")
	require.NoError(t, err)
	require.Len(t, msgA.Answer, 1)
	assert.Equal(t, net.IPv4(10, 0, 0, 1).String(), msgA.Answer[0].(*dns.A).A.String())

	ips, err := LookupIPV6FromContext(context.Background(), addr, "test.local")
	require.NoError(t, err)
	require.Len(t, ips, 1)
	assert.Equal(t, net.ParseIP("::1").String(), ips[0].String())
}

// TestNormalizeEDNS0Answer 覆盖畸形应答的两种形态：OPT 在 ANSWER 段（真实记录
// 被挤到 ADDITIONAL 段）时回收记录并丢弃 OPT；正常应答（OPT 在 ADDITIONAL 段）
// 时保持原样。
func TestNormalizeEDNS0Answer(t *testing.T) {
	newMsg := func() *dns.Msg {
		m := &dns.Msg{}
		m.SetQuestion("example.com.", dns.TypeA)
		return m
	}
	opt := func() *dns.OPT {
		o := new(dns.OPT)
		o.Hdr = dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 1232}
		return o
	}
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("1.2.3.4"),
	}

	// 畸形：OPT 占据 ANSWER 段，A 记录在 ADDITIONAL 段。
	corrupt := newMsg()
	corrupt.Answer = []dns.RR{opt()}
	corrupt.Extra = []dns.RR{a}
	normalizeEDNS0Answer(corrupt)
	if len(corrupt.Answer) != 1 || corrupt.Answer[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("salvaged answer = %v, want the A record", corrupt.Answer)
	}
	if len(corrupt.Extra) != 0 {
		t.Fatalf("extra = %v, want empty", corrupt.Extra)
	}

	// 正常：OPT 在 ADDITIONAL 段，答案保持不动（OPT 仍应被丢弃：本包的查询不带
	// EDNS0，缓存/回放时不需要它）。
	normal := newMsg()
	normal.Answer = []dns.RR{a}
	normal.Extra = []dns.RR{opt()}
	normalizeEDNS0Answer(normal)
	if len(normal.Answer) != 1 || normal.Answer[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("answer = %v, want the A record untouched", normal.Answer)
	}
	if len(normal.Extra) != 0 {
		t.Fatalf("extra = %v, want the OPT dropped", normal.Extra)
	}
}

// TestLookupIPV6FromContextBounded 验证受 context 约束的变体在 context 截止
// 时间到期时能立即返回，而不是等待单次查询的 dnsQueryTimeout。
func TestLookupIPV6FromContextBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := LookupIPV6FromContext(ctx, "127.0.0.1:1", "test.local")
	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second)
}
