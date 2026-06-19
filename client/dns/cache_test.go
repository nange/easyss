package dns

import (
	"testing"

	"github.com/miekg/dns"
)

func TestNewCache(t *testing.T) {
	c := NewCache()
	if c == nil {
		t.Fatal("NewCache returned nil")
	}
	if c.proxied == nil || c.direct == nil {
		t.Error("internal caches should be non-nil")
	}
}

func TestCache_SetAndGet(t *testing.T) {
	c := NewCache()

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
	c := NewCache()

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
	c := NewCache()

	// 未存储的 key 返回 nil
	if got := c.Get("nonexistent.com.", "A", false); got != nil {
		t.Error("expected nil for cache miss")
	}
}

func TestCache_Set_NilMsg(t *testing.T) {
	c := NewCache()

	// nil msg 应不报错
	if err := c.Set(nil, false); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCache_Set_EmptyQuestion(t *testing.T) {
	c := NewCache()

	msg := &dns.Msg{} // 无 Question
	if err := c.Set(msg, false); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCache_Set_NonARecord(t *testing.T) {
	c := NewCache()

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
	c := NewCache()

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
	c := NewCache()

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
