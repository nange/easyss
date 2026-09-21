package dns

import (
	"net"
	"slices"
	"sync"

	"github.com/nange/easyss/v3/client/config"
)

var (
	reachableDNSMu      sync.Mutex
	reachableBuiltinDNS []string // host:port，内置池中成功应答过的，按首次成功顺序
	reachableSystemDNS  []string // host:port，系统 DNS 中成功应答过的，按首次成功顺序
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

	reachableDNSMu.Lock()
	defer reachableDNSMu.Unlock()
	if !slices.Contains(reachableBuiltinDNS, server) {
		reachableBuiltinDNS = append(reachableBuiltinDNS, server)
	}
}

// MarkSystemServerReachable 记录某个系统 DNS 服务器（DHCP/内网解析器）在本会话
// 成功应答过。它只在所有内置 DNS 都不可用、预解析落到系统 DNS 兜底之后才有记录，
// 用来回答"内置全挂时该把哪个地址写进系统解析器"（见 PreferredSystemDNS）：
// 此时回退到内置池首项会把一个当前网络已知不可达的地址写进系统。
//
// 过滤（环回/多播/未指定、非 IPv4）发生在读取时，见 systemDNSHost。
func MarkSystemServerReachable(server string) {
	reachableDNSMu.Lock()
	defer reachableDNSMu.Unlock()
	if !slices.Contains(reachableSystemDNS, server) {
		reachableSystemDNS = append(reachableSystemDNS, server)
	}
}

// clearReachableDNSServers 丢弃可达记录。ResetResolveState 在判定网络状态已变化
// 后调用它：上一次网络里可用的服务器不代表当前网络仍可用。
func clearReachableDNSServers() {
	reachableDNSMu.Lock()
	reachableBuiltinDNS = nil
	reachableSystemDNS = nil
	reachableDNSMu.Unlock()
}

// PreferredSystemDNS 返回 TUN 模式要写入系统解析器配置的裸 IPv4 地址，取值顺序：
//
//  1. 本会话已验证可达的内置直连 DNS —— 正常情况下就是它；
//  2. 否则本会话已验证可达的系统 DNS —— "全部内置 DNS 都不可用、只有 DHCP/内网
//     解析器能用"的网络里，写它才有意义；直连分支会把它作为 reqServer 首选候选
//     与内置池并发竞争，直连解析随之恢复；
//  3. 否则 config.DefaultSystemDNS（等于内置池第一个 IPv4 项）。
//
// 第 3 步与"取内置池首项"是同一个值（client/config 的测试钉住了这个不变量），
// 所以这里不再重复遍历池。
//
// 只取 IPv4：TUN 的 IPv6 路由仅在服务端 IPv6 解析出来后才安装，把 IPv6 解析器
// 写进系统配置在只有 IPv4 的网络上会解析不到。
func PreferredSystemDNS() string {
	reachableDNSMu.Lock()
	defer reachableDNSMu.Unlock()

	for _, server := range reachableBuiltinDNS {
		if host := ipv4Host(server); host != "" {
			return host
		}
	}
	for _, server := range reachableSystemDNS {
		if host := systemDNSHost(server); host != "" {
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

// systemDNSHost 在 ipv4Host 之上再过滤不能写进系统解析器配置的地址。
// 环回是必须过滤的一条：Linux 上 /etc/resolv.conf 常见 systemd-resolved 的
// stub 127.0.0.53，把它写回去会让 resolved 把查询再交给自己，形成解析环。
func systemDNSHost(addr string) string {
	host := ipv4Host(addr)
	if host == "" {
		return ""
	}
	ip := net.ParseIP(host)
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return ""
	}
	return host
}
