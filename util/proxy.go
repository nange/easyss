package util

import "strconv"

// Socks5URI returns the local SOCKS5 endpoint URI for the given port.
func Socks5URI(port int) string {
	return "socks5://127.0.0.1:" + strconv.Itoa(port)
}
