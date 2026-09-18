package dns

import "time"

// ResetResolveState 丢弃内置 DNS 服务器的熔断状态与系统 DNS 服务器发现缓存，
// 使下一次解析重新探测网络。
//
// 开机自启动场景需要它：进程常在网络就绪前启动，第一次解析失败会把内置 DNS
// 服务器熔断 3 分钟（builtinDNSCoolDown），并把空的系统 DNS 列表缓存 5 分钟
// （systemDNSCacheTTL）。后台恢复重试若不先清掉这些状态，就要等它们自然过期
// 才能发现"网络已恢复"，代理可用性会被拖后数分钟。
func ResetResolveState() {
	builtinDNSMu.Lock()
	builtinDNSDown = false
	builtinDNSDownAt = time.Time{}
	builtinDNSMu.Unlock()

	systemDNSMu.Lock()
	systemDNSCached = nil
	systemDNSTime = time.Time{}
	systemDNSMu.Unlock()
}
