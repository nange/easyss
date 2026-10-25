package dns

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/nange/easyss/v3/client/config"
)

func TestNewCache(t *testing.T) {
	t.Parallel()

	c := NewCache("")
	if c == nil {
		t.Fatal("NewCache returned nil")
	}
	if c.proxied == nil || c.direct == nil {
		t.Error("internal caches should be non-nil")
	}
}

func TestCache_SetAndGet(t *testing.T) {
	t.Parallel()

	c := NewCache("")

	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)
	rr, err := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	msg.Answer = append(msg.Answer, rr)

	if err := c.Set(msg, false); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	got := c.Get("example.com.", "A", false)
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(got.Answer))
	}
	if got.Answer[0].Header().Rrtype != dns.TypeA {
		t.Errorf("expected A record")
	}

	// proxied 与 direct 缓存必须隔离。
	if c.Get("example.com.", "A", true) != nil {
		t.Error("direct cache should not have proxied entry")
	}
}

func TestCache_SetAndGet_AAAA(t *testing.T) {
	t.Parallel()

	c := NewCache("")

	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeAAAA)
	rr, err := dns.NewRR("example.com. 3600 IN AAAA ::1")
	if err != nil {
		t.Fatal(err)
	}
	msg.Answer = append(msg.Answer, rr)

	if err := c.Set(msg, true); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	got := c.Get("example.com.", "AAAA", true)
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(got.Answer))
	}
}

func TestCache_Get_Miss(t *testing.T) {
	t.Parallel()

	c := NewCache("")

	if got := c.Get("nonexistent.com.", "A", false); got != nil {
		t.Error("expected nil for cache miss")
	}
}

func TestCache_Set_NilMsg(t *testing.T) {
	t.Parallel()

	c := NewCache("")

	if err := c.Set(nil, false); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCache_Set_EmptyQuestion(t *testing.T) {
	t.Parallel()

	c := NewCache("")

	msg := &dns.Msg{} // 无 Question
	if err := c.Set(msg, false); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCache_Set_NonARecord(t *testing.T) {
	t.Parallel()

	c := NewCache("")

	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeMX)
	rr, err := dns.NewRR("example.com. 3600 IN MX 10 mail.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	msg.Answer = append(msg.Answer, rr)

	if err := c.Set(msg, false); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	// MX 记录不应被缓存。
	if got := c.Get("example.com.", "MX", false); got != nil {
		t.Error("MX records should not be cached")
	}
}

func TestCache_SetNegativeResponse(t *testing.T) {
	t.Parallel()

	newSOA := func(ttl, minttl uint32) *dns.SOA {
		rr, err := dns.NewRR("example.com. 600 IN SOA ns.example.com. host.example.com. 2024010101 3600 600 86400 60")
		if err != nil {
			t.Fatal(err)
		}
		soa := rr.(*dns.SOA)
		soa.Hdr.Ttl = ttl
		soa.Minttl = minttl
		return soa
	}
	newMsg := func(rcode int) *dns.Msg {
		msg := &dns.Msg{}
		msg.SetQuestion("example.com.", dns.TypeA)
		msg.Response = true
		msg.Rcode = rcode
		return msg
	}

	tests := []struct {
		name    string
		rcode   int
		soa     *dns.SOA
		wantTTL int
		wantHit bool
	}{
		{"NODATA with SOA", dns.RcodeSuccess, newSOA(600, 60), 60, true},
		{"NODATA without SOA", dns.RcodeSuccess, nil, 0, false},
		{"NXDOMAIN with SOA", dns.RcodeNameError, newSOA(600, 120), 120, true},
		{"NXDOMAIN without SOA", dns.RcodeNameError, nil, 0, false},
		{"SERVFAIL with SOA", dns.RcodeServerFailure, newSOA(600, 60), 0, false},
		{"NODATA SOA over cap", dns.RcodeSuccess, newSOA(86400, 86400), maxNegativeCacheTTL, true},
		{"NODATA SOA minimum zero", dns.RcodeSuccess, newSOA(600, 0), 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			msg := newMsg(tt.rcode)
			if tt.soa != nil {
				msg.Ns = append(msg.Ns, tt.soa)
			}
			ttl, ok := cacheTTL(msg, "")
			if ok != tt.wantHit {
				t.Fatalf("cacheTTL ok = %v, want %v", ok, tt.wantHit)
			}
			if ok && ttl != tt.wantTTL {
				t.Fatalf("cacheTTL = %d, want %d", ttl, tt.wantTTL)
			}

			c := NewCache("")
			if err := c.Set(msg, false); err != nil {
				t.Fatalf("Set: %v", err)
			}
			got := c.Get("example.com.", "A", false)
			if !tt.wantHit {
				if got != nil {
					t.Fatalf("negative response was cached: %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("negative response was not cached")
			}
			if got.Rcode != tt.rcode {
				t.Fatalf("cached Rcode = %d, want %d", got.Rcode, tt.rcode)
			}
		})
	}
}

func TestCache_Get_UnpackError(t *testing.T) {
	t.Parallel()

	c := NewCache("")

	key := []byte("test.com.A")
	if err := c.proxied.Set(key, []byte("invalid-dns-data"), 3600); err != nil {
		t.Fatal(err)
	}

	if got := c.Get("test.com.", "A", false); got != nil {
		t.Error("expected nil for corrupted cache data")
	}
}

func TestCache_DirectVsProxied(t *testing.T) {
	t.Parallel()

	c := NewCache("")

	msgProxied := &dns.Msg{}
	msgProxied.SetQuestion("example.com.", dns.TypeA)
	rrP, _ := dns.NewRR("example.com. 3600 IN A 1.1.1.1")
	msgProxied.Answer = append(msgProxied.Answer, rrP)
	c.Set(msgProxied, false) //nolint:errcheck

	msgDirect := &dns.Msg{}
	msgDirect.SetQuestion("example.com.", dns.TypeA)
	rrD, _ := dns.NewRR("example.com. 3600 IN A 2.2.2.2")
	msgDirect.Answer = append(msgDirect.Answer, rrD)
	c.Set(msgDirect, true) //nolint:errcheck

	gotP := c.Get("example.com.", "A", false)
	if gotP == nil || gotP.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Error("proxied cache returned wrong IP")
	}

	gotD := c.Get("example.com.", "A", true)
	if gotD == nil || gotD.Answer[0].(*dns.A).A.String() != "2.2.2.2" {
		t.Error("direct cache returned wrong IP")
	}
}

func TestDNSCacheTTL_Clamp(t *testing.T) {
	t.Parallel()

	// TTL 低于下限 clamp 到 1 小时；叠加抖动后普通域名的实际窗口为 60~120 分钟。
	msgLow := &dns.Msg{}
	msgLow.SetQuestion("example.com.", dns.TypeA)
	rrLow, _ := dns.NewRR("example.com. 5 IN A 1.2.3.4")
	msgLow.Answer = append(msgLow.Answer, rrLow)
	if ttl := dnsCacheTTL(msgLow, ""); ttl != 60*60 {
		t.Errorf("low TTL expected %d, got %d", 60*60, ttl)
	} else if eff := jitterTTL(ttl); eff < 60*60 || eff >= 120*60 {
		t.Errorf("low TTL effective window = %d, want in [%d, %d)", eff, 60*60, 120*60)
	}

	// TTL=0 是"立即重新解析"（CDN 切换、动态 DNS），按专门的短下限缓存，不跟着 minCacheTTL 抬高。
	msgZero := &dns.Msg{}
	msgZero.SetQuestion("example.com.", dns.TypeA)
	rrZero, _ := dns.NewRR("example.com. 0 IN A 1.2.3.4")
	msgZero.Answer = append(msgZero.Answer, rrZero)
	if ttl := dnsCacheTTL(msgZero, ""); ttl != 30*60 {
		t.Errorf("zero TTL expected %d, got %d", 30*60, ttl)
	}

	// TTL 高于上限 clamp 到 2 小时。
	msgHigh := &dns.Msg{}
	msgHigh.SetQuestion("example.com.", dns.TypeA)
	rrHigh, _ := dns.NewRR("example.com. 86400 IN A 1.2.3.4")
	msgHigh.Answer = append(msgHigh.Answer, rrHigh)
	if ttl := dnsCacheTTL(msgHigh, ""); ttl != 2*60*60 {
		t.Errorf("high TTL expected %d, got %d", 2*60*60, ttl)
	}

	msgMid := &dns.Msg{}
	msgMid.SetQuestion("example.com.", dns.TypeA)
	rrMid, _ := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
	msgMid.Answer = append(msgMid.Answer, rrMid)
	if ttl := dnsCacheTTL(msgMid, ""); ttl != 3600 {
		t.Errorf("mid TTL expected 3600, got %d", ttl)
	}
}

func TestDNSCacheTTL_ServerDomain(t *testing.T) {
	t.Parallel()

	msg := &dns.Msg{}
	msg.SetQuestion("mysite.net.", dns.TypeA)
	rr, _ := dns.NewRR("mysite.net. 5 IN A 1.2.3.4")
	msg.Answer = append(msg.Answer, rr)

	// 服务器域名大小写不敏感匹配，永不过期。
	if ttl := dnsCacheTTL(msg, "MySite.Net"); ttl != 0 {
		t.Errorf("server domain expected ttl 0, got %d", ttl)
	}

	if ttl := dnsCacheTTL(msg, "other.net"); ttl != 60*60 {
		t.Errorf("non-server domain expected %d, got %d", 60*60, ttl)
	}

	if ttl := dnsCacheTTL(msg, ""); ttl != 60*60 {
		t.Errorf("empty serverDomain expected %d, got %d", 60*60, ttl)
	}
}

func TestCache_ServerDomain_NeverExpires(t *testing.T) {
	t.Parallel()

	c := NewCache("mysite.net")

	msg := &dns.Msg{}
	msg.SetQuestion("mysite.net.", dns.TypeA)
	rr, _ := dns.NewRR("mysite.net. 1 IN A 1.2.3.4")
	msg.Answer = append(msg.Answer, rr)
	if err := c.Set(msg, false); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	// 应答 TTL=1s，服务器域名不受 TTL 影响。
	time.Sleep(1500 * time.Millisecond)
	if got := c.Get("mysite.net.", "A", false); got == nil {
		t.Fatal("server domain entry expired, expected never-expiring cache")
	}

	// 普通域名仍按 clamp 下限缓存（验证 minCacheTTL）。
	c2 := NewCache("")
	msg2 := &dns.Msg{}
	msg2.SetQuestion("example.com.", dns.TypeA)
	rr2, _ := dns.NewRR("example.com. 1 IN A 1.2.3.4")
	msg2.Answer = append(msg2.Answer, rr2)
	if err := c2.Set(msg2, false); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)
	if got := c2.Get("example.com.", "A", false); got == nil {
		t.Fatal("regular domain entry expired before minCacheTTL")
	}
}

func TestJitterTTL_NeverExpire(t *testing.T) {
	t.Parallel()

	// TTL 0（服务器域名永不过期）必须原样返回。
	if ttl := jitterTTL(0); ttl != 0 {
		t.Errorf("jitterTTL(0) expected 0, got %d", ttl)
	}
	// 负数是防御性边界，不应 panic 也不应被改动。
	if ttl := jitterTTL(-1); ttl != -1 {
		t.Errorf("jitterTTL(-1) expected -1, got %d", ttl)
	}
}

func TestJitterTTL_Range(t *testing.T) {
	t.Parallel()

	const base = 1800
	seen := make(map[int]bool)
	for range 1000 {
		ttl := jitterTTL(base)
		// 结果必须在 [base, 2*base) 区间内。
		if ttl < base || ttl >= 2*base {
			t.Fatalf("jitterTTL(%d) = %d, want in [%d, %d)", base, ttl, base, 2*base)
		}
		seen[ttl] = true
	}
	// 1000 次采样下结果应分散。
	if len(seen) < 2 {
		t.Errorf("jitterTTL(%d) always returned %d, expected random jitter", base, base)
	}
}

func TestCachePrePopulateWithFallback(t *testing.T) {
	failAddr := startTestDNSServer(t, true) // 回复 SERVFAIL，快速失败
	okAddr := startTestDNSServer(t, false)  // 正常应答 A/AAAA 记录
	sysServers := systemServersFunc(func() []string {
		return []string{okAddr}
	})
	t.Cleanup(resetBuiltinDNSCircuit)

	c := NewCache("example.com")
	c.system = sysServers
	if err := c.PrePopulateWithFallback(context.Background(), "example.com", []string{failAddr}, true); err != nil {
		t.Fatalf("PrePopulateWithFallback error: %v", err)
	}
	if got := c.Get("example.com.", "A", true); got == nil {
		t.Fatal("direct cache should have the A record after fallback")
	}
}

// TestCachePrePopulateWithFallbackRecordsSystemDNS 验证兜底成功时记录那台系统服务器：TUN 启动据此挑
// 系统解析器，避免把已知不可达的内置地址写进系统。假服务器是环回地址、读取时会被过滤，故直接断言记录值。
func TestCachePrePopulateWithFallbackRecordsSystemDNS(t *testing.T) {
	resetBuiltinDNSCircuit()
	failAddr := startTestDNSServer(t, true)
	okAddr := startTestDNSServer(t, false)
	sysServers := systemServersFunc(func() []string {
		return []string{okAddr}
	})
	t.Cleanup(resetBuiltinDNSCircuit)

	c := NewCache("example.com")
	c.system = sysServers
	if err := c.PrePopulateWithFallback(context.Background(), "example.com", []string{failAddr}, true); err != nil {
		t.Fatalf("PrePopulateWithFallback error: %v", err)
	}

	reachableDNSMu.Lock()
	got := slices.Clone(reachableSystemDNS)
	reachableDNSMu.Unlock()
	if len(got) != 1 || got[0] != okAddr {
		t.Fatalf("reachableSystemDNS = %v, want [%s]", got, okAddr)
	}
	if v := PreferredSystemDNS(); v != config.DefaultSystemDNS {
		t.Fatalf("PreferredSystemDNS = %q, want %q (a loopback system dns must not be used)", v, config.DefaultSystemDNS)
	}
}

func TestCachePrePopulateWithFallbackAllFail(t *testing.T) {
	failAddr := startTestDNSServer(t, true)
	sysServers := systemServersFunc(func() []string {
		return nil
	})
	t.Cleanup(resetBuiltinDNSCircuit)

	c := NewCache("example.com")
	c.system = sysServers
	if err := c.PrePopulateWithFallback(context.Background(), "example.com", []string{failAddr}, true); err == nil {
		t.Fatal("expected error")
	}
	// 没有系统 DNS 兜底时不得熔断内置服务器，否则冷却期内的解析会立刻失败
	if !BuiltinDNSAvailable() {
		t.Fatal("builtin dns must not be tripped when there is no system dns fallback")
	}
}

// TestCachePrePopulateWithFallbackArmedBreakerWithoutSystemDNS 固定熔断置位后兜底消失时，冷却期不得变成
// 彻底的解析中断：仍要尝试内置池，成功后清掉熔断。
func TestCachePrePopulateWithFallbackArmedBreakerWithoutSystemDNS(t *testing.T) {
	resetBuiltinDNSCircuit()
	okAddr := startTestDNSServer(t, false)
	sysServers := systemServersFunc(func() []string {
		return nil
	})
	t.Cleanup(resetBuiltinDNSCircuit)
	MarkBuiltinDNSUnavailable() // 先有兜底、后兜底消失

	c := NewCache("example.com")
	c.system = sysServers
	if err := c.PrePopulateWithFallback(context.Background(), "example.com", []string{okAddr}, true); err != nil {
		t.Fatalf("PrePopulateWithFallback error: %v", err)
	}
	if got := c.Get("example.com.", "A", true); got == nil {
		t.Fatal("direct cache should have the A record after ignoring the armed breaker")
	}
	if !BuiltinDNSAvailable() {
		t.Fatal("a successful builtin query must clear the breaker")
	}
}

// TestCachePrePopulateWithFallbackBlackholeBuiltin 验证内置 DNS 是黑洞时兜底仍能拿到时间预算：黑洞
// 服务器会一直等到截止时间，兜底若复用同一个已过期的 ctx，就会在毫秒内全部失败，哪怕系统 DNS 完全可用。
func TestCachePrePopulateWithFallbackBlackholeBuiltin(t *testing.T) {
	resetBuiltinDNSCircuit()
	blackhole := startBlackholeDNSServer(t)
	okAddr := startTestDNSServer(t, false) // 正常应答 A/AAAA 记录
	sysServers := systemServersFunc(func() []string {
		return []string{okAddr}
	})
	oldItem := ResolveItemTimeout
	ResolveItemTimeout = 100 * time.Millisecond
	t.Cleanup(func() {
		ResolveItemTimeout = oldItem
		resetBuiltinDNSCircuit()
	})

	c := NewCache("example.com")
	c.system = sysServers
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if err := c.PrePopulateWithFallback(ctx, "example.com", []string{blackhole}, true); err != nil {
		t.Fatalf("PrePopulateWithFallback error: %v (a reachable system dns must still be used)", err)
	}
	if got := c.Get("example.com.", "A", true); got == nil {
		t.Fatal("direct cache should have the A record after the system dns fallback")
	}
}

// TestCachePrePopulateQueriesAAndAAAAConcurrently 验证同一个条目的 A 与 AAAA 并发查询：服务器对两种查询都
// 延迟 60% 的条目预算才应答，串行实现只能赶上第一条。预算必须夹在「单条延迟」与「两条串行之和」之间，
// 这是判别并发与串行的唯一依据，但绝对值要给足（本地 UDP 往返、Windows 定时器精度会吃掉几十毫秒）。
func TestCachePrePopulateQueriesAAndAAAAConcurrently(t *testing.T) {
	const (
		itemTimeout = 1 * time.Second        // > 单条延迟，且 < 两条串行之和（1.2s）
		serverDelay = 600 * time.Millisecond // 即预算的 60%，串行实现赶不上第二条
	)

	oldItem := ResolveItemTimeout
	ResolveItemTimeout = itemTimeout
	t.Cleanup(func() { ResolveItemTimeout = oldItem })

	addr := startSlowTestDNSServer(t, serverDelay)

	c := NewCache("example.com")
	if _, err := c.PrePopulate(context.Background(), "example.com", addr, true); err != nil {
		t.Fatalf("PrePopulate error: %v", err)
	}
	if got := c.Get("example.com.", "A", true); got == nil {
		t.Fatal("direct cache should have the A record")
	}
	if got := c.Get("example.com.", "AAAA", true); got == nil {
		t.Fatal("direct cache should have the AAAA record: A and AAAA must run concurrently within one item budget")
	}
}

// TestCachePrePopulateNormalizesCorruptEDNS0Answer 验证"OPT 在 ANSWER 段"的畸形应答不会让预解析失败：
// 被挤到 ADDITIONAL 段的真实记录会被回收进缓存，且不会把 OPT 一起缓存下来。
func TestCachePrePopulateNormalizesCorruptEDNS0Answer(t *testing.T) {
	addr := startCorruptEDNS0DNSServer(t)

	c := NewCache("example.com")
	ips, err := c.PrePopulate(context.Background(), "example.com", addr, true)
	if err != nil {
		t.Fatalf("PrePopulate error: %v", err)
	}
	if want := []string{"1.2.3.4", "2001:db8::1"}; !slices.Equal(ips, want) {
		t.Fatalf("resolved ips = %v, want %v", ips, want)
	}

	got := c.Get("example.com.", "A", true)
	if got == nil || len(got.Answer) == 0 {
		t.Fatal("direct cache should have the A record salvaged from the malformed answer")
	}
	a, ok := got.Answer[0].(*dns.A)
	if !ok || a.A.String() != "1.2.3.4" {
		t.Fatalf("cached answer = %v, want A 1.2.3.4", got.Answer)
	}
	if got.IsEdns0() != nil {
		t.Fatal("cached answer must not carry an OPT record")
	}
}

// TestCachePrePopulateRejectsAnswerWithoutRecords 验证"NOERROR 但没有请求类型的记录"不算解析成功：
// 否则调用方以为服务端域名已解析，而缓存里什么都没有，且该条目还永不过期。
func TestCachePrePopulateRejectsAnswerWithoutRecords(t *testing.T) {
	addr := startNODATADNSServer(t)

	c := NewCache("example.com")
	if _, err := c.PrePopulate(context.Background(), "example.com", addr, true); err == nil {
		t.Fatal("expected error: a NOERROR answer without an A record is not a successful pre-resolve")
	}
	if got := c.Get("example.com.", "A", true); got != nil {
		t.Fatalf("nothing must be cached, got %v", got.Answer)
	}
	if got := c.Get("example.com.", "AAAA", true); got != nil {
		t.Fatalf("nothing must be cached, got %v", got.Answer)
	}
}

func TestCacheServerAddrs(t *testing.T) {
	t.Parallel()

	addr := startTestDNSServer(t, false)
	c := NewCache("example.com")
	if _, err := c.PrePopulate(context.Background(), "example.com", addr, true); err != nil {
		t.Fatalf("PrePopulate error: %v", err)
	}

	want := []string{"1.2.3.4", "2001:db8::1"}
	if got := c.ServerAddrs(); !slices.Equal(got, want) {
		t.Fatalf("ServerAddrs = %v, want %v", got, want)
	}
	if got := NewCache("").ServerAddrs(); got != nil {
		t.Fatalf("ServerAddrs without a server domain = %v, want nil", got)
	}
}

// TestCachePrePopulateWithFallbackBoundedByContext 验证 context 截止时间约束整个预填充过程：
// 否则黑洞服务器会让每种记录类型各等满 5s。
func TestCachePrePopulateWithFallbackBoundedByContext(t *testing.T) {
	blackhole := startBlackholeDNSServer(t)
	sysServers := systemServersFunc(func() []string {
		return nil
	})
	t.Cleanup(resetBuiltinDNSCircuit)

	c := NewCache("example.com")
	c.system = sysServers
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := c.PrePopulateWithFallback(ctx, "example.com", []string{blackhole}, true)
	if err == nil {
		t.Fatal("expected error against blackhole dns server")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("pre-population took %v, want bounded by the context deadline", elapsed)
	}
}

// TestCachePrePopulateDoesNotProbeSystemDNSWhenBuiltinWorks 固定系统 DNS 的惰性获取：内置池成功时不得
// 调用 systemDNSServersFunc（darwin 上走 networksetup，一次约 48ms，而预解析在启动路径上）。
// BuiltinRouteFor 的 hasFailover 因此是惰性函数值而不是 bool——提前求值就会在健康路径上付这笔开销。
func TestCachePrePopulateDoesNotProbeSystemDNSWhenBuiltinWorks(t *testing.T) {
	resetBuiltinDNSCircuit()
	okAddr := startTestDNSServer(t, false)

	probes := 0
	sysServers := systemServersFunc(func() []string {
		probes++
		return nil
	})
	t.Cleanup(resetBuiltinDNSCircuit)

	c := NewCache("example.com")
	c.system = sysServers
	if err := c.PrePopulateWithFallback(context.Background(), "example.com", []string{okAddr}, true); err != nil {
		t.Fatalf("PrePopulateWithFallback error: %v", err)
	}
	if probes != 0 {
		t.Errorf("system DNS was probed %d time(s) while the builtin pool succeeded, want 0", probes)
	}
}
