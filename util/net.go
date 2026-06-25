package util

import (
	"fmt"
	"net"
)

func IsIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func IsLANIP(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}

	return _ip.IsPrivate() || _ip.IsLoopback() || _ip.IsLinkLocalMulticast() || _ip.IsLinkLocalUnicast() ||
		_ip.IsUnspecified() || _ip.IsMulticast() || _ip.IsInterfaceLocalMulticast()
}

func IsLoopbackIP(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}

	return _ip.IsLoopback()
}

// IsLANHost checks whether a host address (with or without port) is a LAN/private address.
// It is used to prevent SSRF attacks by rejecting targets that point to internal networks.
func IsLANHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return IsLANIP(host)
}

func IsIPV6(ip string) bool {
	_ip := net.ParseIP(ip)
	if _ip == nil {
		return false
	}

	if _ip.To4() != nil {
		return false
	} else if _ip.To16() != nil {
		return true
	}

	return false
}

func IsIPV6Addr(addr string) bool {
	host, _, _ := net.SplitHostPort(addr)
	return IsIPV6(host)
}

func GetInterfaceIP(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no ipv4 address found for interface %s", name)
}
