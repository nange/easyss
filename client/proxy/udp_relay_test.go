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

// newDisposableUDPRelay 登记一个使用**真实**（但一次性、测试自有的）UDP socket 的
// 中继，并返回该中继。
//
// 为什么不用 nil socket：这类用例的目标是"中继侧有没有正确拨号/记账"，静默远端
// 不会产生回包，所以 nil 也能跑。但那样中继就失去了回包能力——一旦日后在这些用例
// 里补一条回包断言，或者被中继的代码路径改成先回包，就会在 nil 上 panic。给一个真
// socket 让每条用例都具备完整的回包能力，代价只是每例一个 socket。
func newDisposableUDPRelay(t *testing.T, s *Socks5Server, clientAddr *net.UDPAddr) *udpRelay {
	t.Helper()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen disposable relay socket: %v", err)
	}
	t.Cleanup(func() { socket.Close() }) //nolint:errcheck
	return s.registerTestUDPRelay(socket, clientAddr)
}
