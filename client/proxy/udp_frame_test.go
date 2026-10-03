package proxy

import (
	"fmt"
	"net"
	"testing"
)

// buildUDPFrame 按 SOCKS5 UDP 请求格式手工组帧：RSV(2) + FRAG(1) + ATYP(1) +
// 目标地址 + 目标端口 + 数据，并同时返回解析后的帧与原始字节。
//
// 这里刻意手写线格式而不是调用库的组帧器：旧实现直接借用了
// socks5.NewDatagramFromBytes / socks5.NewDatagram，一旦换库这些调用点就会散落
// 在各测试里。手写一份既让测试独立于具体库，也顺带固化了线格式本身。
func buildUDPFrame(t *testing.T, target string, data []byte) (*socks5Frame, []byte) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split target %q: %v", target, err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}

	var raw []byte
	if ip := net.ParseIP(host).To4(); ip != nil {
		raw = []byte{0, 0, 0, 0x01, ip[0], ip[1], ip[2], ip[3]}
	} else if ip := net.ParseIP(host).To16(); ip != nil {
		raw = append([]byte{0, 0, 0, 0x04}, ip...)
	} else {
		if len(host) > 255 {
			t.Fatalf("host %q is too long for a SOCKS5 domain", host)
		}
		raw = append([]byte{0, 0, 0, 0x03, byte(len(host))}, host...)
	}
	raw = append(raw, byte(port>>8), byte(port))
	raw = append(raw, data...)

	return &socks5Frame{cmd: 0x03, target: target}, raw
}

// parseUDPFrame 解析一条 SOCKS5 UDP 应答帧，返回目标地址（host:port）与载荷。
func parseUDPFrame(t *testing.T, raw []byte) (target string, data []byte) {
	t.Helper()
	if len(raw) < 4 {
		t.Fatalf("datagram is %d bytes, too short for a SOCKS5 header", len(raw))
	}
	atyp := raw[3]
	rest := raw[4:]
	var host string
	switch atyp {
	case 0x01:
		if len(rest) < 4 {
			t.Fatalf("truncated IPv4 address in datagram: %q", raw)
		}
		host = net.IP(rest[:4]).String()
		rest = rest[4:]
	case 0x04:
		if len(rest) < 16 {
			t.Fatalf("truncated IPv6 address in datagram: %q", raw)
		}
		host = net.IP(rest[:16]).String()
		rest = rest[16:]
	case 0x03:
		if len(rest) < 1 {
			t.Fatalf("truncated domain length in datagram: %q", raw)
		}
		n := int(rest[0])
		if len(rest) < 1+n {
			t.Fatalf("truncated domain in datagram: %q", raw)
		}
		host = string(rest[1 : 1+n])
		rest = rest[1+n:]
	default:
		t.Fatalf("unknown atyp %d in datagram: %q", atyp, raw)
	}
	if len(rest) < 2 {
		t.Fatalf("truncated port in datagram: %q", raw)
	}
	port := int(rest[0])<<8 | int(rest[1])
	return fmt.Sprintf("%s:%d", host, port), rest[2:]
}
