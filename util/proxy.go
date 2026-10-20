package util

import (
	"net"
	"strconv"
)

// LocalProxyListenAddr 返回本地代理入口的监听地址：bind_all 时监听 IPv6 通配
// 地址（双栈平台上同时接受 IPv4），否则只监听 IPv4 回环。
func LocalProxyListenAddr(bindAll bool, port int) string {
	if bindAll {
		return net.JoinHostPort("::", strconv.Itoa(port))
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// 通配地址不能拨号，而是否双栈取决于平台（只接受 IPv6 回环的平台拨 127.0.0.1 会连不上），
// 因此按监听地址选同族回环；本进程所有消费方都必须从这里取拨号地址。
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
