package client

import (
	"context"
	"errors"
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

// newDialTestClient 构造一个用于拨号测试的客户端：TUN 关闭（走普通 net.Dialer），
// 服务端域名与 IPv6 规则由调用方指定。
func newDialTestClient(t *testing.T, ipv6Rule, serverAddr string) *Client {
	t.Helper()
	rt, err := router.New(router.Config{IPV6Rule: router.ParseIPV6Rule(ipv6Rule)})
	require.NoError(t, err)
	return &Client{
		cfg: &config.ClientConfig{
			Servers: []*config.ServerProfile{{Address: serverAddr, Default: true}},
			Routing: config.RoutingConfig{IPV6Rule: ipv6Rule},
		},
		router:       rt,
		serverDomain: serverAddr,
	}
}

// TestDialWithConfigUsesServerIPs 验证 DNS pinning：服务端域名无法通过系统解析器
// 解析时，传输层仍然能连上——它拨的是预解析注入的字面 IP（而 TLS 的 SNI 仍来自
// addr 里的域名）。
func TestDialWithConfigUsesServerIPs(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	// server.invalid 在公网 DNS 里不存在（RFC 6761 保留），系统解析器必然失败。
	c := newDialTestClient(t, "disable", "server.invalid")
	c.SetServerIPs([]string{"127.0.0.1"})

	conn, err := c.dialWithConfig(context.Background(), "tcp", net.JoinHostPort("server.invalid", port))
	require.NoError(t, err, "server.invalid is not resolvable; the dial must use the pre-resolved ip")
	defer conn.Close() //nolint:errcheck
	assert.Equal(t, ln.Addr().String(), conn.RemoteAddr().String())
}

// TestDialWithConfigFallsBackWhenServerIPsFail 验证缓存地址过期时的自愈：拨预解析
// 地址失败后丢弃它并回退到域名拨号（系统解析器），而不是一直拨旧地址。
func TestDialWithConfigFallsBackWhenServerIPsFail(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	// localhost 可由系统解析器（/etc/hosts）解析；注入的 127.0.0.2 上没有监听者，
	// 连接会被立即拒绝（而不是等超时），于是回退路径被触发。
	c := newDialTestClient(t, "disable", "localhost")
	c.SetServerIPs([]string{"127.0.0.2"})

	conn, err := c.dialWithConfig(context.Background(), "tcp", net.JoinHostPort("localhost", port))
	require.NoError(t, err, "the domain dial must take over after the stale ip fails")
	defer conn.Close() //nolint:errcheck

	// 失败后缓存地址被丢弃，后续拨号不再尝试旧地址。
	assert.Nil(t, c.serverIPs.Load(), "stale pre-resolved ips must be dropped")
}

// TestWithDomainFallbackReserve 验证 pin 阶段总预算的切分：只有在总预算大于一次
// 拨号预算（serverIPDialTimeout）时才提前扣掉它，保证域名回退至少有一次机会。
func TestWithDomainFallbackReserve(t *testing.T) {
	t.Run("no deadline is left untouched", func(t *testing.T) {
		ctx, cancel := withDomainFallbackReserve(context.Background())
		defer cancel()
		if _, ok := ctx.Deadline(); ok {
			t.Fatal("a context without a deadline must not gain one")
		}
	})

	t.Run("reserves one dial budget", func(t *testing.T) {
		parent, cancelParent := context.WithTimeout(context.Background(), 3*serverIPDialTimeout)
		defer cancelParent()

		ctx, cancel := withDomainFallbackReserve(parent)
		defer cancel()

		got, ok := ctx.Deadline()
		require.True(t, ok, "expected a reserved deadline")
		want, _ := parent.Deadline()
		want = want.Add(-serverIPDialTimeout)
		if diff := got.Sub(want); diff > 50*time.Millisecond || diff < -50*time.Millisecond {
			t.Fatalf("reserved deadline = %v, want %v (±50ms)", got, want)
		}
	})

	t.Run("budget too small is left untouched", func(t *testing.T) {
		parent, cancelParent := context.WithTimeout(context.Background(), serverIPDialTimeout/2)
		defer cancelParent()

		ctx, cancel := withDomainFallbackReserve(parent)
		defer cancel()

		got, _ := ctx.Deadline()
		want, _ := parent.Deadline()
		if !got.Equal(want) {
			t.Fatalf("deadline = %v, want the parent deadline %v untouched", got, want)
		}
	})
}

// TestDialWithConfigReservesBudgetForDomainFallback 覆盖 F1(b)：预解析的字面地址
// 是黑洞（拨号一直等到预算耗尽）时，pin 阶段必须只吃掉总预算里除一次拨号预算以外
// 的部分，域名回退才有机会成功。没有这层预留，域名回退会复用同一个已过期的
// context 在毫秒内失败——即使操作系统解析器完全可用。
func TestDialWithConfigReservesBudgetForDomainFallback(t *testing.T) {
	origBound := boundDialContext
	t.Cleanup(func() { boundDialContext = origBound })

	c := newTestClient(t, true) // TUN 模式：dialAddr 走可注入的 boundDialContext
	c.serverDomain = "server.invalid"
	c.SetServerIPs([]string{"10.255.255.1"})

	var domainDials int
	pinnedBudget := make(chan error, 1)
	boundDialContext = func(_ *Client, ctx context.Context, _ string, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if host == "10.255.255.1" {
			<-ctx.Done() // 黑洞：只收不回，一直等到 pin 阶段预算耗尽
			pinnedBudget <- ctx.Err()
			return nil, ctx.Err()
		}
		domainDials++
		return &net.TCPConn{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), serverIPDialTimeout+200*time.Millisecond)
	defer cancel()

	start := time.Now()
	conn, err := c.dialWithConfig(ctx, "tcp", "server.invalid:443")
	require.NoError(t, err, "the domain fallback must still have budget after the pinned attempt")
	require.NotNil(t, conn)
	if domainDials != 1 {
		t.Fatalf("domain dials = %d, want 1", domainDials)
	}
	if elapsed := time.Since(start); elapsed > serverIPDialTimeout/2 {
		t.Fatalf("pinned phase took %v, want it cut short by the reserve", elapsed)
	}
	if err := <-pinnedBudget; err == nil {
		t.Fatal("the pinned dial must have failed on an exhausted budget")
	}
	assert.Nil(t, c.serverIPs.Load(), "the failed pre-resolved address must be dropped")
}

// TestDialServerIPsStopsWhenBudgetExhausted 验证 pin 阶段预算耗尽后不再逐个尝试
// 剩余字面地址：它们只会各记一次瞬时失败，剩余预算要留给域名回退。
func TestDialServerIPsStopsWhenBudgetExhausted(t *testing.T) {
	origBound := boundDialContext
	t.Cleanup(func() { boundDialContext = origBound })

	c := newTestClient(t, true)
	var calls int
	boundDialContext = func(_ *Client, _ context.Context, _, _ string) (net.Conn, error) {
		calls++
		return nil, errors.New("unreachable")
	}

	expired, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.dialServerIPs(expired, "tcp4", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, "443")
	if err == nil {
		t.Fatal("expected the exhausted budget to be reported")
	}
	if calls != 0 {
		t.Fatalf("dial calls = %d, want 0 after the budget was exhausted", calls)
	}
}
