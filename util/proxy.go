package util

import "strconv"

// Socks5URI 返回指定端口的本地 SOCKS5 端点 URI。
func Socks5URI(port int) string {
	return "socks5://127.0.0.1:" + strconv.Itoa(port)
}
