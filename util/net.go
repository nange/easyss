package util

import (
	"context"
	"fmt"
	"net"
	"time"
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
//
// NOTE: This is a fast, IP-only check. Domain names are NOT resolved here, so a domain
// that resolves to a LAN address will return false. For SSRF protection against
// domain-based bypasses, use IsLANHostResolved instead.
func IsLANHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return IsLANIP(host)
}

// IsLANHostResolved is the SSRF-safe variant of IsLANHost: when the host is a domain
// name rather than a literal IP, it resolves the name and rejects the request if any
// resolved address is a LAN/private address. The fast IP-only path is used when the
// host is already a literal IP, so the common case incurs no DNS lookup.
//
// The provided ctx bounds the DNS resolution so a hung resolver cannot stall the
// handshake.
func IsLANHostResolved(ctx context.Context, addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if IsLANIP(host) {
		return true
	}
	// Literal IP that is not LAN: safe.
	if IsIP(host) {
		return false
	}
	if host == "" {
		return false
	}

	// Domain name: resolve and check every resulting address. A short fallback
	// timeout is applied when the caller's ctx has no deadline, so a slow DNS
	// server cannot hold the handshake open indefinitely.
	resolveCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		resolveCtx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}

	ips, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		// On resolution failure, fail open (return false) so the dial layer can
		// produce the actual error. SSRF protection relies on the next check
		// succeeding; an unresolvable name cannot reach a LAN host anyway.
		return false
	}
	for _, ip := range ips {
		if IsLANIP(ip.IP.String()) {
			return true
		}
	}
	return false
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
