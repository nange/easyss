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

// defaultDNSPort 是没有显式端口时的 DNS 端口：回退上游的条目偶尔是裸地址，补齐端口才不会
// 把"没有端口"误判成"端口不同"，放行一个其实会打回本机的上游。
const defaultDNSPort = "53"

// MarkBuiltinServerReachable 记录某个内置直连 DNS 在本会话成功应答过。非内置池成员会被忽略。
// 记录点只在串行预解析路径上，因此记下的就是池顺序里第一个真正可用的服务器。
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

// MarkSystemServerReachable 记录某个系统 DNS 在本会话成功应答过。它只在预解析落到系统兜底
// 之后才有记录，用来回答"内置全挂时该把哪个地址写进系统解析器"。过滤发生在读取时。
func MarkSystemServerReachable(server string) {
	reachableDNSMu.Lock()
	defer reachableDNSMu.Unlock()
	if !slices.Contains(reachableSystemDNS, server) {
		reachableSystemDNS = append(reachableSystemDNS, server)
	}
}

// clearReachableDNSServers 丢弃可达记录：上一次网络里可用的服务器不代表当前网络仍可用。
func clearReachableDNSServers() {
	reachableDNSMu.Lock()
	reachableBuiltinDNS = nil
	reachableSystemDNS = nil
	reachableDNSMu.Unlock()
}

// PreferredSystemDNS 返回 TUN 模式写入系统解析器配置的裸 IPv4，按可达的内置直连 DNS、可达的
// 系统 DNS、config.DefaultSystemDNS 依次取。只取 IPv4：TUN 的 IPv6 路由要等服务端解析出 IPv6。
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

// systemDNSHost 过滤不能写进系统解析器配置的地址。环回必须过滤：Linux 上 /etc/resolv.conf
// 常见的 systemd-resolved stub 127.0.0.53 写回去会让 resolved 把查询再交给自己，形成解析环。
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

// localAddrSet 返回本机接口上的地址集合（键为 host:port），供转发服务器判断某个回退上游是否
// 会打回自己。不缓存：一次接口枚举是微秒量级，缓存反而会让判定在网络切换后过期。
func localAddrSet(port string) map[string]struct{} {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	addrs := make(map[string]struct{})
	for _, iface := range ifaces {
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range ifaceAddrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			// To4 把 IPv4-mapped 地址（::ffff:1.2.3.4）与 IPv4 字面值归一化成同一个键。
			ip := ipnet.IP
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			addrs[net.JoinHostPort(ip.String(), port)] = struct{}{}
		}
	}
	return addrs
}

// isSelfUpstreamAddr 报告回退上游 addr 是否会把查询打回本机监听地址。先看端口：本机另一端口上
// 的解析器不会打回；端口相同时环回/未指定地址算本机，落在本机接口地址集合里的也算。
func isSelfUpstreamAddr(addr, listenAddr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// 无端口的裸地址按默认 DNS 端口参与判断，否则一个被写成裸 IP 的上游会被当成
		// "打不到本机"而放行。
		host, port = addr, defaultDNSPort
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	_, listenPort, err := net.SplitHostPort(listenAddr)
	if err != nil {
		listenPort = defaultDNSPort
	}
	if port != listenPort {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	_, ok := localAddrSet(port)[net.JoinHostPort(ip.String(), port)]
	return ok
}
