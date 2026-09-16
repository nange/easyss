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
func QueryWithBuiltinFirst(builtin, system []string, try func(servers []string) (*dns.Msg, error)) (*dns.Msg, error) {
	if len(builtin) == 0 {
		return try(system)
	}
	if BuiltinDNSAvailable() {
		reply, err := try(builtin)
		if err == nil {
			MarkBuiltinDNSAvailable()
			return reply, nil
		}
		MarkBuiltinDNSUnavailable()
		log.Warn("[DNS] all builtin dns servers failed, fallback to system dns", "err", err)
	}
	return try(system)
}
