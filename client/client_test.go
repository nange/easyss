package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/client/config"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startLocalDNSServer 启动一个本地 UDP DNS 服务器，对 "test.local." 的 AAAA 查询
// 以 ::1 应答（与 client/dns/lookup_test.go 中的做法一致）。
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
	// 黑洞直连 DNS 服务器会让每次解析都失败；上下文截止时间必须约束整个解析过程，
	// 而不是让每次查询 5 秒的超时拖慢启动。
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

// TestRefreshServerIPV6 覆盖 RefreshServerIPV6 的短路路径与"降级启动后重新
// 解析"的正向路径：只有当前值为空、服务器是域名且 IPv6 规则未禁用时才查询。
func TestRefreshServerIPV6(t *testing.T) {
	newClient := func(t *testing.T, cfg *config.ClientConfig) *Client {
		t.Helper()
		rt, err := router.New(router.Config{
			ProxyRule: router.ParseProxyRule(cfg.Routing.ProxyRule),
			IPV6Rule:  router.ParseIPV6Rule(cfg.Routing.IPV6Rule),
		})
		require.NoError(t, err)
		return &Client{cfg: cfg, router: rt}
	}
	domainCfg := func(rule string) *config.ClientConfig {
		return &config.ClientConfig{
			Servers: []*config.ServerProfile{{Address: "proxy.example.com", Default: true}},
			Routing: config.RoutingConfig{IPV6Rule: rule},
		}
	}

	// nil 客户端安全返回空串。
	var nilClient *Client
	assert.Equal(t, "", nilClient.RefreshServerIPV6())

	// 已有解析结果：直接返回，不重新查询。
	c := newClient(t, domainCfg("auto"))
	c.router.SetIPV6Info(false, "2001:db8::1")
	assert.Equal(t, "2001:db8::1", c.RefreshServerIPV6())

	// 服务器是字面 IPv4：无需解析。
	c = newClient(t, &config.ClientConfig{
		Servers: []*config.ServerProfile{{Address: "1.2.3.4", Default: true}},
		Routing: config.RoutingConfig{IPV6Rule: "auto"},
	})
	assert.Equal(t, "", c.RefreshServerIPV6())

	// IPv6 规则禁用：不解析。
	c = newClient(t, domainCfg("disable"))
	assert.Equal(t, "", c.RefreshServerIPV6())

	// 正向路径：本地 DNS 应答 AAAA ::1，结果写回路由引擎。
	addr, shutdown := startLocalDNSServer(t)
	defer shutdown()

	old := config.DirectDNSServers
	config.DirectDNSServers = []string{addr}
	defer func() { config.DirectDNSServers = old }()
	easydns.MarkBuiltinDNSAvailable()

	cfg := &config.ClientConfig{
		Servers: []*config.ServerProfile{{Address: "test.local", Default: true}},
		Routing: config.RoutingConfig{IPV6Rule: "auto"},
	}
	c = newClient(t, cfg)
	assert.Equal(t, net.ParseIP("::1").String(), c.RefreshServerIPV6())
	assert.Equal(t, net.ParseIP("::1").String(), c.router.ServerIPV6())
}
