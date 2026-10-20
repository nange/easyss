package proxy

import (
	"net"
	"testing"
)

// 本文件承载 UDP 中继的测试辅助。它们原本放在生产文件 socks5.go 里，但没有任何
// 生产代码路径会调用它们（只被 _test.go 使用），因此移到这里。

// registerTestUDPRelay 直接构造并登记一个中继，供不经过 ASSOCIATE 握手的测试使用
// （例如直接调用 handleUDP / sendToClient / directUDPRelay 的用例）。
func (s *Socks5Server) registerTestUDPRelay(socket *net.UDPConn, clientAddr *net.UDPAddr) *udpRelay {
	r := &udpRelay{socket: socket, clientIP: clientAddr.IP, peer: clientAddr}
	s.addUDPRelay(r)
	return r
}

// udpRelayCount 返回当前存活的中继数量。
func (s *Socks5Server) udpRelayCount() int {
	s.udpMu.RLock()
	defer s.udpMu.RUnlock()
	return len(s.udpRelays)
}

// newDisposableUDPRelay 登记一个使用真实一次性 UDP socket 的中继：nil socket 也能跑
// 现有用例，但中继会失去回包能力，补一条回包断言就会 panic。
func newDisposableUDPRelay(t *testing.T, s *Socks5Server, clientAddr *net.UDPAddr) *udpRelay {
	t.Helper()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen disposable relay socket: %v", err)
	}
	t.Cleanup(func() { socket.Close() }) //nolint:errcheck
	return s.registerTestUDPRelay(socket, clientAddr)
}
