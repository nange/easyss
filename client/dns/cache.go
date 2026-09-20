package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
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
// 当 requireIPv4 为 true 时，A 查询必须成功；否则 A 或 AAAA 任一成功即可。
// ctx 约束整个解析过程，这样不可达的 DNS 服务器不会因单次查询 5s 的超时
// 而拖慢启动。
func (c *Cache) PrePopulate(ctx context.Context, domain, dnsServer string, requireIPv4 bool) error {
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

	var ok bool
	var aErr error
	if msgA, err := DNSMsgTypeAContext(ctx, dnsServer, domain); err == nil {
		store(msgA)
		ok = true
	} else {
		aErr = err
		log.Warn("[DNS] PrePopulate type A", "domain", domain, "err", err)
	}

	if msgAAAA, err := DNSMsgTypeAAAAContext(ctx, dnsServer, domain); err == nil {
		store(msgAAAA)
		if !requireIPv4 {
			ok = true
		}
	} else {
		log.Warn("[DNS] PrePopulate type AAAA", "domain", domain, "err", err)
	}

	if !ok {
		if requireIPv4 && aErr != nil {
			return fmt.Errorf("failed to resolve %s A record via %s: %w", domain, dnsServer, aErr)
		}
		return fmt.Errorf("failed to resolve %s via %s", domain, dnsServer)
	}
	return nil
}

// PrePopulateWithFallback 依次通过给定的每个 DNS 服务器解析域名，当它们全部
// 不可用时回退到系统 DNS 服务器，并将结果同时存入直连与代理缓存。
// requireIPv4 的语义见 PrePopulate。
// ctx 约束整个解析过程（见 PrePopulate）。
//
// 与 QueryWithBuiltinFirst 一致：只有存在系统 DNS 兜底时才会熔断内置服务器，
// 否则冷却期会变成"每次解析都立刻失败"的解析中断。
func (c *Cache) PrePopulateWithFallback(ctx context.Context, domain string, dnsServers []string, requireIPv4 bool) error {
	var lastErr error
	try := func(server string) bool {
		err := c.PrePopulate(ctx, domain, server, requireIPv4)
		if err == nil {
			return true
		}
		lastErr = errors.Join(lastErr, err)
		log.Warn("[DNS] PrePopulate via dns server failed", "domain", domain, "server", server, "err", err)
		return false
	}

	if BuiltinDNSAvailable() {
		if slices.ContainsFunc(dnsServers, try) {
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
			log.Warn("[DNS] all builtin dns servers failed, fallback to system dns", "domain", domain, "err", lastErr)
		} else {
			log.Debug("[DNS] all builtin dns servers failed and no system dns is available", "domain", domain, "err", lastErr)
		}

		if slices.ContainsFunc(systemServers, try) {
			return nil
		}
	} else if slices.ContainsFunc(systemDNSServersFunc(), try) {
		return nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no dns server available for %s", domain)
	}
	return lastErr
}
