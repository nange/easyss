package dns

import "time"

// 清掉内置 DNS 熔断、可达记录与系统 DNS 发现缓存，让下一次解析重新探测网络。后台恢复重试必须
// 在每次尝试前调用：开机网络未就绪会熔断 3 分钟并缓存空系统 DNS 列表 5 分钟，不清就要等它们过期。
func ResetResolveState() {
	builtinDNSMu.Lock()
	builtinDNSDown = false
	builtinDNSDownAt = time.Time{}
	builtinDNSMu.Unlock()

	clearReachableDNSServers()
	defaultSystemDNS.reset()
}
