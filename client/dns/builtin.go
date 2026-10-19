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

// BuiltinAttempt 是"这次要不要试内置 DNS、失败后要不要熔断"的**唯一判定**，
// 以两个有名字的返回值同时给出这两个决定：把它们拆成两个函数会让调用方分别
// 判断，而它们必须一起应用（漏掉任一半都会把 3 分钟冷却变成别的行为）。
//
// 规则只有一条：**只有确实存在系统 DNS 兜底时才熔断内置池**。没有兜底时熔断，
// 会让冷却期内每一次解析都在这条空回退上立刻失败（try([]) 立即返回错误，而不是
// 超时）；反过来，熔断已置位但当前没有兜底时应当**无视冷却**继续试——那 3 分钟
// 冷却可能是在"当时还有系统 DNS"的情况下置位的，而 Android 上系统 DNS 对应用
// 不可见正是这种"只有内置 DNS 可用"的情形。
//
// 三个调用点共享本判定，但各自保留自己的循环：QueryWithBuiltinFirst 的并发
// 竞争取首个成功、PrePopulateWithFallback 的串行加预算、client.resolveServerIPV6
// 的逐条目预算——三者的调度与预算模型本来就不同，合并循环会破坏各自的超时语义。
func BuiltinAttempt(systemFailover bool) (try, armOnFailure bool) {
	return BuiltinDNSAvailable() || !systemFailover, systemFailover
}

// QueryWithBuiltinFirst 先使用 try 查询内置 DNS 服务器，当它们不可用时回退
// 到系统 DNS 服务器。失败后的冷却期内会完全跳过内置服务器，因此持续不可达
// 的内置 DNS 不会因超时而拖慢每一次查询。
//
// system 必须是调用方过滤后的可用上游列表：真正拨不通的条目（指向本机转发
// 服务器的自环地址、ipv6_rule=disable 下的 IPv6 地址）不应被算作兜底。
// 熔断判定由 BuiltinAttempt 统一提供，本函数只负责「内置优先、失败后回退」
// 这一种循环形态。
func QueryWithBuiltinFirst(builtin, system []string, try func(servers []string) (*dns.Msg, error)) (*dns.Msg, error) {
	if len(builtin) == 0 {
		return try(system)
	}
	attempt, armOnFailure := BuiltinAttempt(len(system) > 0)
	if attempt {
		reply, err := try(builtin)
		if err == nil {
			MarkBuiltinDNSAvailable()
			return reply, nil
		}
		if armOnFailure {
			MarkBuiltinDNSUnavailable()
			log.Warn("[DNS] all builtin dns servers failed, fallback to system dns", "err", err)
		} else {
			// 无兜底时不熔断，因此这里会随每次查询重复出现；调用方的失败
			// 日志（如 [DNS_DIRECT] 的 Error）才是这条路径的可见信号。
			log.Debug("[DNS] all builtin dns servers failed and no system dns is available", "err", err)
		}
	}
	return try(system)
}
