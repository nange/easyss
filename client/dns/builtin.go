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

// QueryWithBuiltinFirst 先使用 try 查询内置 DNS 服务器，当它们不可用时回退
// 到系统 DNS 服务器。失败后的冷却期内会完全跳过内置服务器，因此持续不可达
// 的内置 DNS 不会因超时而拖慢每一次查询。
//
// system 必须是调用方过滤后的可用上游列表：真正拨不通的条目（指向本机转发
// 服务器的自环地址、ipv6_rule=disable 下的 IPv6 地址）不应被算作兜底。
//
// 只有确实存在兜底上游时才会熔断内置服务器。system 为空时不熔断：没有回退
// 目标时熔断只会让冷却期内的每一次查询都在空列表上立刻失败（try([]) 立即
// 返回错误，而不是超时），从而把 3 分钟冷却变成彻底的解析中断——Android 上
// 系统 DNS 对应用不可见，正是这种"只有内置 DNS 可用"的情形。
func QueryWithBuiltinFirst(builtin, system []string, try func(servers []string) (*dns.Msg, error)) (*dns.Msg, error) {
	if len(builtin) == 0 {
		return try(system)
	}
	// 没有兜底上游时无视熔断：熔断可能是在"当时还有系统 DNS"的情况下置位的，
	// 而现在 system 已经为空，跳过内置池会让冷却期内的每一次查询都在空列表上
	// 立刻失败（try([]) 立即返回错误，而不是超时），把 3 分钟冷却变成彻底的解析
	// 中断——Android 上系统 DNS 对应用不可见，正是这种"只有内置 DNS 可用"的情形。
	if BuiltinDNSAvailable() || len(system) == 0 {
		reply, err := try(builtin)
		if err == nil {
			MarkBuiltinDNSAvailable()
			return reply, nil
		}
		if len(system) > 0 {
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
