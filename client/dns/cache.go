package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"

	"github.com/coocood/freecache"
	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/stats"
)

const (
	cacheSize = 2 * 1024 * 1024
	// 上游 TTL 常在 60~300 秒，照搬会让经隧道的 DNS 查询过于频繁；再叠加 jitterTTL 的抖动，
	// 实际命中窗口为 60~120 分钟。
	minCacheTTL = 60 * 60
	// TTL=0 表示"立即重新解析"，这类记录不能跟着 minCacheTTL 一起被抬高。
	zeroTTLCacheTTL = 30 * 60
	// 抖动在 clamp 之后施加，实际窗口为 2~4 小时。
	maxCacheTTL = 2 * 60 * 60
)

type Cache struct {
	proxied      *freecache.Cache
	direct       *freecache.Cache
	serverDomain string
}

// serverDomain（通常是代理服务器自己的域名）的条目永不过期，TTL 到期不会触发针对它的
// 并发直连查询突发。
func NewCache(serverDomain string) *Cache {
	return &Cache{
		proxied:      freecache.NewCache(cacheSize),
		direct:       freecache.NewCache(cacheSize),
		serverDomain: serverDomain,
	}
}

func (c *Cache) Get(name, qtype string, isDirect bool) *dns.Msg {
	cache := c.proxied
	if isDirect {
		cache = c.direct
	}
	// DNS 名称不区分大小写，统一归一化后不同大小写的查询命中同一条目。
	v, err := cache.Get([]byte(strings.ToLower(name) + qtype))
	if err != nil || len(v) == 0 {
		stats.RecordDNSCacheMiss()
		return nil
	}
	msg := &dns.Msg{}
	if err := msg.Unpack(v); err != nil {
		stats.RecordDNSCacheMiss()
		return nil
	}
	stats.RecordDNSCacheHit()
	return msg
}

// 只缓存 A 与 AAAA 记录，有效时长是基础 TTL 加上随机抖动。
func (c *Cache) Set(msg *dns.Msg, isDirect bool) error {
	if msg == nil || len(msg.Question) == 0 {
		return nil
	}
	q := msg.Question[0]
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
		v, err := msg.Pack()
		if err != nil {
			return err
		}
		key := []byte(strings.ToLower(q.Name) + dns.TypeToString[q.Qtype])
		ttl := jitterTTL(dnsCacheTTL(msg, c.serverDomain))
		if isDirect {
			return c.direct.Set(key, v, ttl)
		}
		return c.proxied.Set(key, v, ttl)
	}
	return nil
}

// 代理服务器自身域名返回 0（freecache 中表示永不过期），其余按应答中最小 TTL 限制在
// [minCacheTTL, maxCacheTTL] 内。
func dnsCacheTTL(msg *dns.Msg, serverDomain string) int {
	if serverDomain != "" {
		q := msg.Question[0]
		domain := strings.TrimSuffix(q.Name, ".")
		if strings.EqualFold(domain, serverDomain) {
			return 0
		}
	}
	ttl := uint32(maxCacheTTL)
	for _, rr := range msg.Answer {
		if rr == nil || rr.Header() == nil {
			continue
		}
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	if ttl == 0 {
		return zeroTTLCacheTTL
	}
	if ttl > maxCacheTTL {
		ttl = maxCacheTTL
	}
	if ttl < minCacheTTL {
		ttl = minCacheTTL
	}
	return int(ttl)
}

// TTL 为 0（永不过期）时原样返回。
func jitterTTL(ttl int) int {
	if ttl <= 0 {
		return ttl
	}
	return ttl + rand.IntN(ttl)
}

// 通过指定 DNS 服务器解析域名并把结果存入两个缓存。requireIPv4 为 true 时 A 查询必须成功，
// 否则任一类型带回地址即可。NOERROR 但应答里没有请求类型的记录不算成功。
func (c *Cache) PrePopulate(ctx context.Context, domain, dnsServer string, requireIPv4 bool) ([]string, error) {
	store := func(msg *dns.Msg) {
		if msg == nil {
			return
		}
		if err := c.Set(msg, true); err != nil {
			log.Warn("[DNS] PrePopulate set direct cache", "domain", domain, "err", err)
		}
		if err := c.Set(msg, false); err != nil {
			log.Warn("[DNS] PrePopulate set proxy cache", "domain", domain, "err", err)
		}
	}

	// 每个条目独立预算：黑洞服务器最多吃掉一项的时间，系统兜底仍有机会。
	itemCtx, cancelItem := context.WithTimeout(ctx, ResolveItemTimeout)
	defer cancelItem()

	type result struct {
		msg *dns.Msg
		err error
	}
	query := func(qtype uint16) <-chan result {
		ch := make(chan result, 1)
		go func() {
			msg, err := queryMsg(itemCtx, qtype, dnsServer, domain)
			ch <- result{msg: msg, err: err}
		}()
		return ch
	}

	aCh := query(dns.TypeA)
	aaaaCh := query(dns.TypeAAAA)

	var ok bool
	var aErr error
	var addrs []string

	if r := <-aCh; r.err != nil {
		aErr = r.err
		log.Warn("[DNS] PrePopulate type A", "domain", domain, "server", dnsServer, "err", r.err)
	} else if !msgHasRecord(r.msg, dns.TypeA) {
		aErr = errNoRecordInAnswer
		log.Warn("[DNS] PrePopulate type A", "domain", domain, "server", dnsServer, "err", aErr)
	} else {
		store(r.msg)
		addrs = append(addrs, answerAddrs(r.msg)...)
		ok = true
	}

	if r := <-aaaaCh; r.err != nil {
		log.Warn("[DNS] PrePopulate type AAAA", "domain", domain, "server", dnsServer, "err", r.err)
	} else if !msgHasRecord(r.msg, dns.TypeAAAA) {
		// AAAA 的 NODATA 是正常现象（域名只有 IPv4），不是错误也不算成功。
		log.Debug("[DNS] PrePopulate type AAAA no record in the answer",
			"domain", domain, "server", dnsServer)
	} else {
		store(r.msg)
		addrs = append(addrs, answerAddrs(r.msg)...)
		if !requireIPv4 {
			ok = true
		}
	}

	if !ok {
		if requireIPv4 && aErr != nil {
			return nil, fmt.Errorf("failed to resolve %s A record via %s: %w", domain, dnsServer, aErr)
		}
		return nil, fmt.Errorf("failed to resolve %s via %s", domain, dnsServer)
	}
	return addrs, nil
}

var errNoRecordInAnswer = errors.New("no record of the requested type in the answer")

func msgHasRecord(msg *dns.Msg, qtype uint16) bool {
	if msg == nil {
		return false
	}
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

// 返回 serverDomain 已缓存的 A/AAAA 地址（A 在前），供客户端拨号做 DNS pinning。不记录命中
// 统计：这是内部消费，不是一次真实解析。
func (c *Cache) ServerAddrs() []string {
	if c.serverDomain == "" {
		return nil
	}

	name := strings.ToLower(dns.Fqdn(c.serverDomain))
	var addrs []string
	for _, qtype := range []string{dns.TypeToString[dns.TypeA], dns.TypeToString[dns.TypeAAAA]} {
		v, err := c.direct.Get([]byte(name + qtype))
		if err != nil || len(v) == 0 {
			continue
		}
		msg := &dns.Msg{}
		if err := msg.Unpack(v); err != nil {
			continue
		}
		addrs = append(addrs, answerAddrs(msg)...)
	}
	return addrs
}

func answerAddrs(msg *dns.Msg) []string {
	if msg == nil {
		return nil
	}
	var addrs []string
	for _, rr := range msg.Answer {
		switch a := rr.(type) {
		case *dns.A:
			addrs = append(addrs, a.A.String())
		case *dns.AAAA:
			addrs = append(addrs, a.AAAA.String())
		}
	}
	return addrs
}

// 依次通过给定的 DNS 服务器解析，全部不可用时回退系统 DNS。内置分支受预留量约束，使系统
// 兜底至少有一个完整条目的预算。
func (c *Cache) PrePopulateWithFallback(ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error {
	// 内置分支只能花掉总预算里除预留量以外的部分：否则系统兜底会复用一个已过期的 ctx，
	// 在毫秒内全部失败。
	builtinCtx, cancelBuiltin := WithSystemDNSFallbackReserve(ctx)
	defer cancelBuiltin()

	var lastErr error
	try := func(qctx context.Context, server string) ([]string, bool) {
		ips, err := c.PrePopulate(qctx, domain, server, requireIPv4)
		if err == nil {
			return ips, true
		}
		lastErr = errors.Join(lastErr, err)
		log.Warn("[DNS] PrePopulate via dns server failed", "domain", domain, "server", server, "err", err)
		return nil, false
	}

	// 记录成功过的内置服务器，供 TUN 启动时挑选系统 DNS（见 PreferredSystemDNS）。
	tryBuiltin := func(server string) bool {
		ips, ok := try(builtinCtx, server)
		if !ok {
			return false
		}
		MarkBuiltinServerReachable(server)
		log.Info("[DNS] domain resolved via builtin dns server",
			"domain", domain, "server", server, "ips", ips)
		return true
	}

	// 记录系统兜底成功的服务器：全部内置 DNS 都不可用时，TUN 启动需要知道"这台确实能用"。
	trySystem := func(server string) bool {
		ips, ok := try(ctx, server)
		if !ok {
			return false
		}
		MarkSystemServerReachable(server)
		log.Info("[DNS] domain resolved via system fallback dns server (builtin dns servers unavailable)",
			"domain", domain, "server", server, "ips", ips)
		return true
	}

	// 分支预算耗尽即停止：继续调用只会对每台剩下的服务器再记一条瞬时失败日志（拨号根本
	// 没发生），把日志刷爆且误导排查。
	tryAll := func(qctx context.Context, servers []string, try func(string) bool) bool {
		for i, server := range servers {
			if qctx.Err() != nil {
				log.Warn("[DNS] pre-resolve budget exhausted, skipping remaining dns servers",
					"domain", domain, "skipped", len(servers)-i, "err", qctx.Err())
				return false
			}
			if try(server) {
				return true
			}
		}
		return false
	}

	// 惰性获取系统 DNS：健康路径不会为一次预解析付出系统 DNS 发现的开销（见 BuiltinRouteFor）。
	var systemServers []string
	systemLoaded := false
	loadSystem := func() []string {
		if !systemLoaded {
			systemServers = systemDNSServersFunc()
			systemLoaded = true
		}
		return systemServers
	}

	switch BuiltinRouteFor(func() bool { return len(loadSystem()) > 0 }) {
	case BuiltinRouteSkip:
		if tryAll(ctx, loadSystem(), trySystem) {
			return nil
		}

	case BuiltinRouteRetry:
		// 熔断生效但没有任何兜底时无视冷却继续试内置池；必须记日志，否则与健康路径无法区分。
		log.Warn("[DNS] builtin dns breaker is armed but no system dns is available, retrying builtin servers",
			"domain", domain)
		if tryAll(builtinCtx, dnsServers, tryBuiltin) {
			MarkBuiltinDNSAvailable()
			return nil
		}

	default: // BuiltinRouteFirst
		if tryAll(builtinCtx, dnsServers, tryBuiltin) {
			MarkBuiltinDNSAvailable()
			return nil
		}

		// 只有确实存在系统兜底时才熔断。
		servers := loadSystem()
		if len(servers) > 0 {
			MarkBuiltinDNSUnavailable()
			log.Warn("[DNS] all builtin dns servers failed, fallback to system dns",
				"domain", domain, "system_servers", servers, "err", lastErr)
		} else {
			log.Debug("[DNS] all builtin dns servers failed and no system dns is available",
				"domain", domain, "err", lastErr)
		}
		if tryAll(ctx, servers, trySystem) {
			return nil
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no dns server available for %s", domain)
	}
	return lastErr
}
