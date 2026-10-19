package dns

import (
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/log"
)

// builtinDNSCoolDown 是当一次查询中所有内置 DNS 服务器都失败后，跳过这些
// 内置 DNS 服务器的时间长度，这样持续不可达的内置 DNS（例如被网络屏蔽）就
// 不会因超时而拖慢每一次查询。冷却期结束后允许一次重试，以便网络恢复后能
// 再次被探测到。
const builtinDNSCoolDown = 3 * time.Minute

var (
	builtinDNSMu     sync.Mutex
	builtinDNSDown   bool
	builtinDNSDownAt time.Time
)

// BuiltinDNSAvailable 报告内置 DNS 服务器是否应被尝试用于本次查询。在
// MarkBuiltinDNSUnavailable 之后的冷却期内返回 false，查询将直接走系统 DNS
// 服务器；冷却期结束后允许一次重试。
func BuiltinDNSAvailable() bool {
	builtinDNSMu.Lock()
	defer builtinDNSMu.Unlock()
	if !builtinDNSDown {
		return true
	}
	return time.Since(builtinDNSDownAt) >= builtinDNSCoolDown
}

// MarkBuiltinDNSUnavailable 将内置 DNS 服务器标记为不可用，并在
// builtinDNSCoolDown 期间跳过它们。当针对所有内置 DNS 服务器的查询都失败时
// 调用。
func MarkBuiltinDNSUnavailable() {
	builtinDNSMu.Lock()
	builtinDNSDown = true
	builtinDNSDownAt = time.Now()
	builtinDNSMu.Unlock()
}

// MarkBuiltinDNSAvailable 清除不可用状态，当针对某个内置 DNS 服务器的查询
// 成功时调用。
func MarkBuiltinDNSAvailable() {
	builtinDNSMu.Lock()
	builtinDNSDown = false
	builtinDNSMu.Unlock()
}

// BuiltinRoute 描述本次解析应当如何使用内置池。三个状态是互斥的，调用方用
// switch 显式处理每一支——此前用两个布尔表示同一件事，"熔断中但没有兜底"这一态
// 与"健康"态在调用方看起来一样，于是其中一条分支永远不可达，日志也永远不打印。
type BuiltinRoute uint8

const (
	// BuiltinRouteFirst 表示熔断器健康：先试内置池，失败后回退系统兜底。
	BuiltinRouteFirst BuiltinRoute = iota
	// BuiltinRouteSkip 表示熔断生效且存在系统兜底：直接用系统 DNS，不碰内置池。
	BuiltinRouteSkip
	// BuiltinRouteRetry 表示熔断生效但当前没有任何系统兜底：无视冷却继续试内置池
	// ——跳过它会把 3 分钟冷却变成彻底的解析中断（Android 上系统 DNS 对应用不可见
	// 正是这种"只有内置 DNS 可用"的情形）。
	BuiltinRouteRetry
)

// String 供日志使用。
func (r BuiltinRoute) String() string {
	switch r {
	case BuiltinRouteSkip:
		return "skip-builtin"
	case BuiltinRouteRetry:
		return "retry-builtin"
	default:
		return "builtin-first"
	}
}

// BuiltinRouteFor 是"这次要不要试内置 DNS"的**唯一判定**。
//
// hasFailover 惰性求值：熔断器健康时根本不会调用它，因此正常路径不会为一次
// 预解析付出系统 DNS 发现的开销（darwin 上走 networksetup，约 48ms；虽有 5 分钟
// 缓存，但把这次进程外调用挪到"熔断已置位"这条罕见路径上仍然值得）。
//
// 熔断规则只有一条：**只有确实存在系统 DNS 兜底时才跳过内置池**。没有兜底还
// 跳过，会让冷却期内每一次解析都在空列表上立刻失败（而不是超时）。
//
// 三个调用点共享本判定，但各自保留自己的循环：QueryWithBuiltinFirst 的并发
// 竞争取首个成功、PrePopulateWithFallback 的串行加预算、client.resolveServerIPV6
// 的逐条目预算——三者的调度与预算模型本来就不同，合并循环会破坏各自的超时语义。
func BuiltinRouteFor(hasFailover func() bool) BuiltinRoute {
	if BuiltinDNSAvailable() {
		return BuiltinRouteFirst
	}
	if hasFailover() {
		return BuiltinRouteSkip
	}
	return BuiltinRouteRetry
}

// QueryWithBuiltinFirst 先使用 try 查询内置 DNS 服务器，当它们不可用时回退
// 到系统 DNS 服务器。失败后的冷却期内会完全跳过内置服务器，因此持续不可达
// 的内置 DNS 不会因超时而拖慢每一次查询。
//
// system 必须是调用方过滤后的可用上游列表：真正拨不通的条目（指向本机转发
// 服务器的自环地址、ipv6_rule=disable 下的 IPv6 地址）不应被算作兜底。
// 熔断判定由 BuiltinRouteFor 统一提供，本函数只负责「内置优先、失败后回退」
// 这一种循环形态。
func QueryWithBuiltinFirst(builtin, system []string, try func(servers []string) (*dns.Msg, error)) (*dns.Msg, error) {
	if len(builtin) == 0 {
		return try(system)
	}
	route := BuiltinRouteFor(func() bool { return len(system) > 0 })
	if route == BuiltinRouteSkip {
		return try(system)
	}
	if route == BuiltinRouteRetry {
		// 熔断已置位但没有兜底：明确记录"冷却被无视"，否则这条路径在日志里
		// 与健康路径完全无法区分。
		log.Warn("[DNS] builtin dns breaker is armed but no system dns is available, retrying builtin servers")
	}
	reply, err := try(builtin)
	if err == nil {
		MarkBuiltinDNSAvailable()
		return reply, nil
	}
	// 熔断规则：只有存在系统兜底时才置位。无兜底时熔断会让冷却期变成彻底中断，
	// 因此这里会随每次查询重复出现——调用方的失败日志（如 [DNS_DIRECT] 的
	// Error）才是这条路径的可见信号。
	if len(system) > 0 {
		MarkBuiltinDNSUnavailable()
		log.Warn("[DNS] all builtin dns servers failed, fallback to system dns", "err", err)
	} else {
		log.Debug("[DNS] all builtin dns servers failed and no system dns is available", "err", err)
	}
	return try(system)
}
