package util

import (
	"net"
	"strconv"
)

// LocalProxyListenAddr 返回本地代理入口（SOCKS5/HTTP）的监听地址：bind_all 时
// 监听 IPv6 通配地址（双栈平台上同时接受 IPv4，覆盖所有本地 IP），否则只监听
// IPv4 回环。
func LocalProxyListenAddr(bindAll bool, port int) string {
	if bindAll {
		return net.JoinHostPort("::", strconv.Itoa(port))
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// LocalProxyDialAddr 返回本进程（含提权 TUN 辅助进程）拨本地代理入口时使用的
// 地址。它由监听地址唯一推导，而不是再写一份 bind_all 判断：通配地址不能作为
// 拨号目标，而监听实际只接受 IPv6 的平台（例如不支持 IPv4-mapped 的 BSD，或
// IPV6_V6ONLY 无法覆盖的环境）只接受 IPv6 回环，拨 127.0.0.1 会连不上。
//
// linux/darwin/windows 上 Go 通常会把 [::] 通配监听设为双栈（显式
// IPV6_V6ONLY=0），此时 127.0.0.1 往往也能连上；这里按监听地址选同族回环，
// 是为了不依赖该实现细节，并让所有本地消费方（HTTP 入口的反向代理、TUN 引擎、
// TUN 辅助进程、系统代理与会话环境）的拨号方向始终与 bind_all 同源。
func LocalProxyDialAddr(bindAll bool, port int) string {
	listenAddr := LocalProxyListenAddr(bindAll, port)

	host, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return listenAddr
	}
	switch host {
	case "::":
		return net.JoinHostPort("::1", portStr)
	case "", "0.0.0.0":
		return net.JoinHostPort("127.0.0.1", portStr)
	default:
		return listenAddr
	}
}

// Socks5URI 返回指向本地 SOCKS5 入口的 URI（拨号地址见 LocalProxyDialAddr）。
func Socks5URI(bindAll bool, port int) string {
	return "socks5://" + LocalProxyDialAddr(bindAll, port)
}
