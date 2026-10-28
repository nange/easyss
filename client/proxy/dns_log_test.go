package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
)

func TestDNSLogOnceMarksFirstOnly(t *testing.T) {
	t.Parallel()

	var s dnsLogOnce
	key := dnsLogKey("example.com", "A")
	if !s.mark(key) {
		t.Fatal("first mark should report first")
	}
	if s.mark(key) {
		t.Fatal("repeat mark should not report first")
	}
	if !s.mark(dnsLogKey("example.com", "AAAA")) {
		t.Fatal("A and AAAA must be tracked independently")
	}
}

func TestDNSLogOnceEvictsOldest(t *testing.T) {
	t.Parallel()

	var s dnsLogOnce
	for i := range dnsLogOnceCap {
		if !s.mark(fmt.Sprintf("d%d.example.com", i)) {
			t.Fatalf("mark %d should be first", i)
		}
	}

	// 集合满后只有插入新键才淘汰最旧的键。
	if !s.mark("new.example.com") {
		t.Fatal("a new key must still be first")
	}
	if !s.mark("d0.example.com") {
		t.Fatal("the evicted key should be first again")
	}
	if s.mark(fmt.Sprintf("d%d.example.com", dnsLogOnceCap-1)) {
		t.Fatal("a recent key should still be remembered")
	}
}

func TestPlanMarksFirstQueryOnce(t *testing.T) {
	t.Parallel()

	d := newTestDNSInterceptor(t, router.IPV6RuleAuto, "")
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	if !d.plan(query).first {
		t.Fatal("first plan should mark the query as first")
	}
	if d.plan(query).first {
		t.Fatal("second plan must not mark the query as first")
	}

	aaaa := new(dns.Msg)
	aaaa.SetQuestion("example.com.", dns.TypeAAAA)
	if !d.plan(aaaa).first {
		t.Fatal("AAAA is a separate resolution and should be first")
	}
}

func TestDNSLogKeyIgnoresCase(t *testing.T) {
	t.Parallel()

	if a, b := dnsLogKey("WWW.Example.COM", "A"), dnsLogKey("www.example.com", "A"); a != b {
		t.Fatalf("dnsLogKey must normalize case: %q != %q", a, b)
	}
}

func TestPlanSeparatesUnknownQTypes(t *testing.T) {
	t.Parallel()

	d := newTestDNSInterceptor(t, router.IPV6RuleAuto, "")
	question := func(qtype uint16) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("odd.example.com.", qtype)
		return msg
	}

	if !d.plan(question(65000)).first {
		t.Fatal("the first query should be first")
	}
	if !d.plan(question(65001)).first {
		t.Fatal("unknown qtypes must not share a dedupe key")
	}
}

// 以下用例替换全局 logger，属进程级共享状态，不能并行。

func TestFirstSyncQueryLoggedAtInfo(t *testing.T) {
	rec := captureLogs(t)
	d := newTestDNSInterceptor(t, router.IPV6RuleAuto, startTestDNSResponder(t))

	query := new(dns.Msg)
	query.SetQuestion("direct.example.com.", dns.TypeA)
	ex := dnsExchange{
		plan: dnsPlan{action: dnsActionDirect, domain: "direct.example.com", qtype: "A", first: true},
		src:  "src",
		dst:  "dst",
	}

	if _, err := d.executeSync(ex, query, ""); err != nil {
		t.Fatalf("executeSync: %v", err)
	}
	ex.plan.first = false
	if _, err := d.executeSync(ex, query, ""); err != nil {
		t.Fatalf("executeSync repeat: %v", err)
	}

	for _, msg := range []string{"[DNS_DIRECT]", "[DNS_DIRECT] result"} {
		if got := rec.count(slog.LevelInfo, msg); got != 1 {
			t.Fatalf("%q should be logged at info once, got %d", msg, got)
		}
		if got := rec.count(slog.LevelDebug, msg); got != 1 {
			t.Fatalf("%q should be logged at debug once for the repeat query, got %d", msg, got)
		}
	}
}

func TestFirstProxiedAnswerLoggedAtInfo(t *testing.T) {
	rec := captureLogs(t)
	d := newTestDNSInterceptor(t, router.IPV6RuleAuto, "")

	query := new(dns.Msg)
	query.SetQuestion("proxied.example.com.", dns.TypeA)
	for range 2 {
		resp := new(dns.Msg)
		resp.SetReply(query)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name: "proxied.example.com.", Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: 60,
			},
			A: net.ParseIP("1.2.3.4"),
		})
		d.finishProxied(resp, "proxied.example.com", "src", "dst")
	}

	if got := rec.count(slog.LevelInfo, "[DNS_PROXY] result"); got != 1 {
		t.Fatalf("first proxied answer should be logged at info once, got %d", got)
	}
	if got := rec.count(slog.LevelDebug, "[DNS_PROXY] result"); got != 1 {
		t.Fatalf("repeat proxied answer should be logged at debug once, got %d", got)
	}
}

// 首次命中缓存时 Info 行要带应答，并消费首答：缓存过期后的第一次真实解析不应再留下
// 没有 query 行配对的 result 行。
func TestFirstCacheHitLogsAnswersAndConsumesAnswer(t *testing.T) {
	rec := captureLogs(t)
	d := newTestDNSInterceptor(t, router.IPV6RuleAuto, "")

	query := new(dns.Msg)
	query.SetQuestion("cached.example.com.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "cached.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("1.2.3.4"),
	})
	// 命中哪一份缓存取决于内置直连列表，两份都填，只固定"命中"这件事。
	for _, isDirect := range []bool{true, false} {
		if err := d.cache.Set(resp, isDirect); err != nil {
			t.Fatalf("cache.Set(direct=%v): %v", isDirect, err)
		}
	}

	if plan := d.plan(query); plan.action != dnsActionCacheHit {
		t.Fatalf("action = %v, want cache-hit", plan.action)
	}
	if got := rec.count(slog.LevelInfo, "[DNS_CACHE] hit"); got != 1 {
		t.Fatalf("first cache hit should be logged at info once, got %d", got)
	}
	if got := rec.attr(slog.LevelInfo, "[DNS_CACHE] hit", "answers"); !strings.Contains(got, "1.2.3.4") {
		t.Fatalf("first cache hit should carry the cached answers, got %q", got)
	}

	if plan := d.plan(query); plan.first {
		t.Fatal("second plan must not report first")
	}
	if got := rec.count(slog.LevelDebug, "[DNS_CACHE] hit"); got != 1 {
		t.Fatalf("repeat cache hit should be logged at debug once, got %d", got)
	}

	d.finishProxied(resp, "cached.example.com", "src", "dst")
	if got := rec.count(slog.LevelInfo, "[DNS_PROXY] result"); got != 0 {
		t.Fatalf("cache hit already consumed the first answer, got %d info result lines", got)
	}
	if got := rec.count(slog.LevelDebug, "[DNS_PROXY] result"); got != 1 {
		t.Fatalf("repeat answer should be logged at debug once, got %d", got)
	}
}

// recordHandler 记录全部日志记录，供按级别与消息计数。加锁是因为上一个用例遗留的
// 后台 goroutine 可能在本用例换上记录器之后才写出日志。
type recordHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordHandler) count(level slog.Level, msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	n := 0
	for _, r := range h.records {
		if r.Level == level && r.Message == msg {
			n++
		}
	}
	return n
}

// attr 返回第一条匹配 (level, msg) 记录上 key 的字符串值。
func (h *recordHandler) attr(level slog.Level, msg, key string) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, r := range h.records {
		if r.Level != level || r.Message != msg {
			continue
		}
		var got string
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == key {
				got = a.Value.String()
				return false
			}
			return true
		})
		return got
	}
	return ""
}

// captureLogs 把全局 logger 换成记录器；全局 logger 是进程级状态，调用方不得并行。
func captureLogs(t *testing.T) *recordHandler {
	t.Helper()

	h := &recordHandler{}
	prev := log.Logger()
	log.SetLogger(slog.New(h))
	t.Cleanup(func() { log.SetLogger(prev) })
	return h
}

func newTestDNSInterceptor(t *testing.T, ipv6Rule router.IPV6Rule, dnsAddr string) *dnsInterceptor {
	t.Helper()

	rt, err := router.New(router.Config{ProxyRule: router.ProxyRuleAuto, IPV6Rule: ipv6Rule})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	d := &dnsInterceptor{
		router:      rt,
		cache:       easydns.NewCache(""),
		respTimeout: time.Second,
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var nd net.Dialer
			return nd.DialContext(ctx, network, addr)
		},
	}
	if dnsAddr != "" {
		// 直连分支会并发查询内置公共 DNS：统一拨到本地应答器，既不出网也不依赖内置列表。
		d.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var nd net.Dialer
			return nd.DialContext(ctx, network, dnsAddr)
		}
	}
	return d
}

// startTestDNSResponder 在本地 UDP 端口上返回固定的 A 记录，供直连解析用例替换上游。
func startTestDNSResponder(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var query dns.Msg
			if err := query.Unpack(buf[:n]); err != nil || len(query.Question) == 0 {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(&query)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name: query.Question[0].Name, Rrtype: dns.TypeA,
					Class: dns.ClassINET, Ttl: 60,
				},
				A: net.ParseIP("1.2.3.4"),
			})
			if packed, err := resp.Pack(); err == nil {
				_, _ = pc.WriteTo(packed, addr)
			}
		}
	}()

	return pc.LocalAddr().String()
}
