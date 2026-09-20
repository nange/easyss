package dns

import (
	"net"
	"slices"
	"sync"

	"github.com/nange/easyss/v3/client/config"
)

var (
	reachableBuiltinMu sync.Mutex
	reachableBuiltin   []string // host:port，按首次成功顺序
)

// MarkBuiltinServerReachable 记录某个内置直连 DNS 服务器在本会话成功应答过。
// 非内置池成员会被忽略，这样测试里替换 config.DirectDNSServers 后使用的本地
// 假服务器不会污染记录。
//
// 记录点是启动期与后台重试期的串行预解析路径（dns.Cache.PrePopulateWithFallback
// 与 client.resolveServerIPV6）：它们按内置池顺序逐个尝试、首个成功即返回，
// 因此记录下来的就是"按池顺序第一个真正可用的服务器"。
func MarkBuiltinServerReachable(server string) {
	if !slices.Contains(config.DirectDNSServers, server) {
		return
	}

	reachableBuiltinMu.Lock()
	defer reachableBuiltinMu.Unlock()
	if !slices.Contains(reachableBuiltin, server) {
		reachableBuiltin = append(reachableBuiltin, server)
	}
}

// clearReachableBuiltinServers 丢弃可达记录。ResetResolveState 在判定网络状态
// 已变化后调用它：上一次网络里可用的服务器不代表当前网络仍可用。
func clearReachableBuiltinServers() {
	reachableBuiltinMu.Lock()
	reachableBuiltin = nil
	reachableBuiltinMu.Unlock()
}

// PreferredSystemDNS 返回 TUN 模式要写入系统解析器配置的裸 IPv4 地址：
// 优先返回本会话已验证可达的内置服务器；没有记录（例如启动时网络未就绪、
// 或全部内置服务器都不可用而走了系统 DNS 兜底）时回退到内置池第一个 IPv4 项，
// 池为空时回退到 config.DefaultSystemDNS。
//
// 只取 IPv4：TUN 的 IPv6 路由仅在服务端 IPv6 解析出来后才安装，把 IPv6 解析器
// 写进系统配置在只有 IPv4 的网络上会解析不到。
func PreferredSystemDNS() string {
	reachableBuiltinMu.Lock()
	defer reachableBuiltinMu.Unlock()

	for _, server := range reachableBuiltin {
		if host := ipv4Host(server); host != "" {
			return host
		}
	}
	for _, server := range config.DirectDNSServers {
		if host := ipv4Host(server); host != "" {
			return host
		}
	}
	return config.DefaultSystemDNS
}

// ipv4Host 返回 host:port 形式地址的裸 IPv4；不是 IPv4（含 IPv6、裸地址解析
// 失败）时返回空字符串。
func ipv4Host(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return host
}
