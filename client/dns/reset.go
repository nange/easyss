package dns

import "time"

// ResetResolveState 丢弃内置 DNS 服务器的熔断状态、解析器可达记录与系统
// DNS 服务器发现缓存，使下一次解析重新探测网络。
//
// 开机自启动场景需要它：进程常在网络就绪前启动，第一次解析失败会把内置 DNS
// 服务器熔断 3 分钟（builtinDNSCoolDown），并把空的系统 DNS 列表缓存 5 分钟
// （systemDNSCacheTTL）。后台恢复重试若不先清掉这些状态，就要等它们自然过期
// 才能发现"网络已恢复"，代理可用性会被拖后数分钟。
//
// 可达记录（PreferredSystemDNS 的数据源，内置与系统两份）同样要清：网络变化后
// 上一次网络里可用的服务器不再代表当前网络可用。
func ResetResolveState() {
	builtinDNSMu.Lock()
	builtinDNSDown = false
	builtinDNSDownAt = time.Time{}
	builtinDNSMu.Unlock()

	clearReachableDNSServers()

	systemDNSMu.Lock()
	systemDNSCached = nil
	systemDNSTime = time.Time{}
	systemDNSMu.Unlock()
}
