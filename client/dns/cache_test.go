package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNewCache(t *testing.T) {
	c := NewCache("")
	if c == nil {
		t.Fatal("NewCache returned nil")
	}
	if c.proxied == nil || c.direct == nil {
		t.Error("internal caches should be non-nil")
	}
}

func TestCache_SetAndGet(t *testing.T) {
	c := NewCache("")

	// 构造 A 记录查询响应
	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)
	rr, err := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	msg.Answer = append(msg.Answer, rr)

	// 存入 proxied 缓存
	if err := c.Set(msg, false); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	// 从 proxied 缓存读取
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

	// proxied 和 direct 缓存隔离
	if c.Get("example.com.", "A", true) != nil {
		t.Error("direct cache should not have proxied entry")
	}
}

func TestCache_SetAndGet_AAAA(t *testing.T) {
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
	c := NewCache("")

	// 未存储的 key 返回 nil
	if got := c.Get("nonexistent.com.", "A", false); got != nil {
		t.Error("expected nil for cache miss")
	}
}

func TestCache_Set_NilMsg(t *testing.T) {
	c := NewCache("")

	// nil msg 应不报错
	if err := c.Set(nil, false); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCache_Set_EmptyQuestion(t *testing.T) {
	c := NewCache("")

	msg := &dns.Msg{} // 无 Question
	if err := c.Set(msg, false); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCache_Set_NonARecord(t *testing.T) {
	c := NewCache("")

	// MX 记录不应被缓存
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

	// MX 记录不应被缓存，所以 Get 应返回 nil
	if got := c.Get("example.com.", "MX", false); got != nil {
		t.Error("MX records should not be cached")
	}
}

func TestCache_Get_UnpackError(t *testing.T) {
	c := NewCache("")

	// 直接写入损坏的数据到内部缓存
	key := []byte("test.com.A")
	if err := c.proxied.Set(key, []byte("invalid-dns-data"), 3600); err != nil {
		t.Fatal(err)
	}

	// 解包失败应返回 nil
	if got := c.Get("test.com.", "A", false); got != nil {
		t.Error("expected nil for corrupted cache data")
	}
}

func TestCache_DirectVsProxied(t *testing.T) {
	c := NewCache("")

	// 存储到 proxied
	msgProxied := &dns.Msg{}
	msgProxied.SetQuestion("example.com.", dns.TypeA)
	rrP, _ := dns.NewRR("example.com. 3600 IN A 1.1.1.1")
	msgProxied.Answer = append(msgProxied.Answer, rrP)
	c.Set(msgProxied, false)

	// 存储到 direct
	msgDirect := &dns.Msg{}
	msgDirect.SetQuestion("example.com.", dns.TypeA)
	rrD, _ := dns.NewRR("example.com. 3600 IN A 2.2.2.2")
	msgDirect.Answer = append(msgDirect.Answer, rrD)
	c.Set(msgDirect, true)

	// proxied → 1.1.1.1
	gotP := c.Get("example.com.", "A", false)
	if gotP == nil || gotP.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Error("proxied cache returned wrong IP")
	}

	// direct → 2.2.2.2
	gotD := c.Get("example.com.", "A", true)
	if gotD == nil || gotD.Answer[0].(*dns.A).A.String() != "2.2.2.2" {
		t.Error("direct cache returned wrong IP")
	}
}

func TestDNSCacheTTL_Clamp(t *testing.T) {
	// TTL 低于下限 → clamp 到 30 分钟
	msgLow := &dns.Msg{}
	msgLow.SetQuestion("example.com.", dns.TypeA)
	rrLow, _ := dns.NewRR("example.com. 5 IN A 1.2.3.4")
	msgLow.Answer = append(msgLow.Answer, rrLow)
	if ttl := dnsCacheTTL(msgLow, ""); ttl != 30*60 {
		t.Errorf("low TTL expected %d, got %d", 30*60, ttl)
	}

	// TTL 高于上限 → clamp 到 2 小时
	msgHigh := &dns.Msg{}
	msgHigh.SetQuestion("example.com.", dns.TypeA)
	rrHigh, _ := dns.NewRR("example.com. 86400 IN A 1.2.3.4")
	msgHigh.Answer = append(msgHigh.Answer, rrHigh)
	if ttl := dnsCacheTTL(msgHigh, ""); ttl != 2*60*60 {
		t.Errorf("high TTL expected %d, got %d", 2*60*60, ttl)
	}

	// TTL 在区间内 → 取应答最小 TTL
	msgMid := &dns.Msg{}
	msgMid.SetQuestion("example.com.", dns.TypeA)
	rrMid, _ := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
	msgMid.Answer = append(msgMid.Answer, rrMid)
	if ttl := dnsCacheTTL(msgMid, ""); ttl != 3600 {
		t.Errorf("mid TTL expected 3600, got %d", ttl)
	}
}

func TestDNSCacheTTL_ServerDomain(t *testing.T) {
	msg := &dns.Msg{}
	msg.SetQuestion("mysite.net.", dns.TypeA)
	rr, _ := dns.NewRR("mysite.net. 5 IN A 1.2.3.4")
	msg.Answer = append(msg.Answer, rr)

	// 服务器域名（大小写不敏感匹配）→ 永不过期
	if ttl := dnsCacheTTL(msg, "MySite.Net"); ttl != 0 {
		t.Errorf("server domain expected ttl 0, got %d", ttl)
	}

	// 非服务器域名 → 正常 clamp
	if ttl := dnsCacheTTL(msg, "other.net"); ttl != 30*60 {
		t.Errorf("non-server domain expected %d, got %d", 30*60, ttl)
	}

	// serverDomain 为空时不受影响
	if ttl := dnsCacheTTL(msg, ""); ttl != 30*60 {
		t.Errorf("empty serverDomain expected %d, got %d", 30*60, ttl)
	}
}

func TestCache_ServerDomain_NeverExpires(t *testing.T) {
	c := NewCache("mysite.net")

	msg := &dns.Msg{}
	msg.SetQuestion("mysite.net.", dns.TypeA)
	rr, _ := dns.NewRR("mysite.net. 1 IN A 1.2.3.4")
	msg.Answer = append(msg.Answer, rr)
	if err := c.Set(msg, false); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	// 应答 TTL=1s，普通域名 1s 后即过期；服务器域名需保持命中
	time.Sleep(1500 * time.Millisecond)
	if got := c.Get("mysite.net.", "A", false); got == nil {
		t.Fatal("server domain entry expired, expected never-expiring cache")
	}

	// 普通域名仍按 clamp 下限缓存（1s 后仍命中，验证 minCacheTTL）
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
