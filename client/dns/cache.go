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
	cacheSize   = 2 * 1024 * 1024
	maxCacheTTL = 2 * 60 * 60
	minCacheTTL = 30 * 60
)

// Cache 将 DNS 查询结果存储在两个独立的缓存中：一个用于代理（proxied）
// 结果，一个用于直连（direct）结果。
type Cache struct {
	proxied      *freecache.Cache
	direct       *freecache.Cache
	serverDomain string
}

// NewCache 创建一个 DNS 缓存，代理与直连结果分开存储。serverDomain（通常为
// 代理服务器自身的域名）对应的条目永不过期，这样 TTL 到期永远不会触发针对
// 它的并发直连查询突发。
func NewCache(serverDomain string) *Cache {
	return &Cache{
		proxied:      freecache.NewCache(cacheSize),
		direct:       freecache.NewCache(cacheSize),
		serverDomain: serverDomain,
	}
}

// Get 按名称和查询类型获取缓存的 DNS 消息。
// 若 isDirect 为 true 则查询直连缓存，否则查询代理缓存。
func (c *Cache) Get(name, qtype string, isDirect bool) *dns.Msg {
	cache := c.proxied
	if isDirect {
		cache = c.direct
	}
	// DNS 名称不区分大小写；统一归一化，使不同大小写的查询命中同一条目。
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

// Set 使用 DNS TTL 将 DNS 消息存入对应的缓存。
// 仅缓存 A 和 AAAA 记录。若 isDirect 为 true 则使用直连缓存。
// 有效缓存时长为基础 TTL 加上 [0, baseTTL) 范围内的随机抖动，使具有相同
// 基础 TTL 的条目不会在同一时刻过期，避免并发 DNS 查询的突发。
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

// dnsCacheTTL 返回给定 DNS 消息的缓存时长（秒）。代理服务器自身域名的条目
// 永不过期（freecache 中 0 表示永不过期）；其他域名按应答中最小 TTL 缓存，
// 并限制在 [minCacheTTL, maxCacheTTL] 区间内。
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
		// TTL 为 0 通常表示“立即重新解析”（CDN 故障切换、动态 DNS）。将其
		// 限制到 *最小* 缓存时长而不是最大时长，这样对新鲜度要求高的记录
		// 不会滞留 2 小时。
		ttl = minCacheTTL
	}
	if ttl > maxCacheTTL {
		ttl = maxCacheTTL
	}
	if ttl < minCacheTTL {
		ttl = minCacheTTL
	}
	return int(ttl)
}

// jitterTTL 返回基础 TTL 对应的有效缓存时长（秒）：基础 TTL 加上 [0, ttl)
// 范围内的随机抖动。因此共享同一基础 TTL 的条目会在分散的时刻过期，而不是
// 同时过期，从而避免并发 DNS 查询的突发。TTL 为 0（永不过期，例如代理服务器
// 自身域名）时原样返回。
func jitterTTL(ttl int) int {
	if ttl <= 0 {
		return ttl
	}
	return ttl + rand.IntN(ttl)
}

// PrePopulate 通过指定的 DNS 服务器解析域名，并将 A 和 AAAA 结果同时存入
// 直连与代理缓存。用于在 TUN 路由生效前预置代理服务器 IP 的缓存，避免 DNS
// 死锁。
// 当 requireIPv4 为 true 时，A 查询必须成功且必须带回地址；否则 A 或 AAAA
// 任一"带回地址"即可。
// 这台服务器的 A 与 AAAA 查询并发进行，共享 ResolveItemTimeout 这一项预算：
// 一个条目的耗时上限就是它，而不是两种记录各自超时之和。
//
// 成功必须意味着"缓存里真的拿到了地址"：NOERROR 但应答里没有请求类型的记录
// （NODATA，或被畸形应答吃掉）不算成功，否则调用方会据此认为服务端域名已解析，
// 而缓存里其实什么都没有。返回成功时拿到并存入缓存的地址（A 在前、AAAA 在后），
// 供调用方记录"是谁解析出来的、解析成了什么"。
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

	// 每个条目独立预算：黑洞服务器最多吃掉一项的时间，池里其余项与系统兜底
	// 都还有机会（见 ResolveItemTimeout）。
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
		// AAAA 的 NODATA 是正常现象（域名只有 IPv4）：不是错误，也不算成功。
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

// errNoRecordInAnswer 表示解析器应答了 NOERROR，但应答里没有请求类型的记录。
var errNoRecordInAnswer = errors.New("no record of the requested type in the answer")

// msgHasRecord 报告应答的 ANSWER 段里是否含有指定类型的记录（CNAME 链末端的
// 目标记录同样按类型统计）。
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

// ServerAddrs 返回 serverDomain 已缓存的 A/AAAA 地址（A 在前、AAAA 在后），
// 供客户端拨号做 DNS pinning（见 client.Client.SetServerIPs）。
//
// 它不记录缓存命中统计：这是内部消费，不是一次真实解析。没有 serverDomain
// 或没有缓存条目时返回 nil。
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

// answerAddrs 返回应答里 A/AAAA 记录的地址字符串（按记录顺序）。
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

// PrePopulateWithFallback 依次通过给定的每个 DNS 服务器解析域名，当它们全部
// 不可用时回退到系统 DNS 服务器，并将结果同时存入直连与代理缓存。
// requireIPv4 的语义见 PrePopulate。
// ctx 约束整个解析过程（见 PrePopulate）：每个条目受 ResolveItemTimeout 限制，
// 整个内置分支再受预留量约束，使系统 DNS 兜底至少有一个完整条目的预算
// （见 WithSystemDNSFallbackReserve）。
//
// 它记录成功应答过的服务器（内置分支 MarkBuiltinServerReachable，系统兜底
// 分支 MarkSystemServerReachable），因此调用方在它成功之后可以通过
// PreferredSystemDNS 拿到"本会话实测可用的解析器"。
//
// 与 QueryWithBuiltinFirst 一致：只有存在系统 DNS 兜底时才会熔断内置服务器，
// 否则冷却期会变成"每次解析都立刻失败"的解析中断。
func (c *Cache) PrePopulateWithFallback(ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error {
	// 内置分支只能花掉总预算里除预留量以外的部分：黑洞内置服务器（丢包而非立即
	// 拒绝）会把整个预算耗在一次查询上，若系统兜底复用同一个已过期的 ctx，它会
	// 在毫秒内全部失败——系统 DNS 明明可用（见 WithSystemDNSFallbackReserve）。
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

	// 内置分支额外记录成功过的服务器，供 TUN 启动时挑选系统 DNS（见
	// PreferredSystemDNS）；系统 DNS 兜底成功不算内置服务器可达。
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

	// 系统 DNS 兜底成功时记录这台系统服务器：全部内置 DNS 都不可用的网络里，
	// TUN 启动需要知道"这台确实能用"，才不会把一个当前网络已知不可达的内置
	// 地址写进系统解析器配置。
	// 成功日志显式说明"这次是操作系统兜底 DNS 解析的"并打出那台服务器的地址，
	// 否则日志里只有内置服务器的一串超时，看不出结果是谁给的。
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

	// tryAll 按顺序尝试服务器，一旦该分支的预算耗尽就停止：继续调用只会对
	// 每台剩下的服务器再记一条瞬时失败日志（拨号根本没发生），把日志刷爆且
	// 误导排查。
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

	if BuiltinDNSAvailable() {
		if tryAll(builtinCtx, dnsServers, tryBuiltin) {
			MarkBuiltinDNSAvailable()
			return nil
		}

		// 惰性获取系统 DNS：内置可用时不应为此付出一次系统 DNS 发现的开销。
		systemServers := systemDNSServersFunc()
		// 只有确实存在系统 DNS 兜底时才熔断内置服务器。无兜底时熔断会让冷却
		// 期内每一次解析都在这条空回退上立刻失败，而内置服务器此时仍可能可用
		// （Android 上系统 DNS 对应用不可见，正是这种情形）。
		if len(systemServers) > 0 {
			MarkBuiltinDNSUnavailable()
			log.Warn("[DNS] all builtin dns servers failed, fallback to system dns",
				"domain", domain, "system_servers", systemServers, "err", lastErr)
		} else {
			log.Debug("[DNS] all builtin dns servers failed and no system dns is available", "domain", domain, "err", lastErr)
		}

		if tryAll(ctx, systemServers, trySystem) {
			return nil
		}
	} else {
		// 熔断已置位：正常跳过内置服务器。但它可能是在"当时还有系统兜底"的情况下
		// 置位的，而现在兜底已经消失（Android 上系统 DNS 对应用不可见，正是这种
		// 情形）——此时冷却期会变成彻底的解析中断。没有兜底就无视冷却，仍然尝试
		// 内置池。
		systemServers := systemDNSServersFunc()
		if len(systemServers) == 0 {
			log.Warn("[DNS] builtin dns breaker is armed but no system dns is available, retrying builtin servers",
				"domain", domain)
			if tryAll(builtinCtx, dnsServers, tryBuiltin) {
				MarkBuiltinDNSAvailable()
				return nil
			}
		} else if tryAll(ctx, systemServers, trySystem) {
			return nil
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no dns server available for %s", domain)
	}
	return lastErr
}
