package proxy

import (
	"net"
	"testing"
	"time"
)

// TestSendToClientFramesReplyFromClientTarget 守住应答必须用客户端查询的来源地址组帧：
// tun2socks 在对称 NAT 模式下以该地址为 UDP 流建键，用上游地址组帧的应答会被丢弃。
func TestSendToClientFramesReplyFromClientTarget(t *testing.T) {
	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client socket: %v", err)
	}
	t.Cleanup(func() { clientConn.Close() }) //nolint:errcheck

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen server socket: %v", err)
	}
	t.Cleanup(func() { serverConn.Close() }) //nolint:errcheck

	// SOCKS5 侧在这里只用到 srv.UDPConn，所以一个裸服务器就够了：
	// 不涉及监听器、处理器或传输层。
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)
	s := &Socks5Server{}
	relay := s.registerTestUDPRelay(serverConn, clientAddr)
	s.sendToClient(relay, []byte("answer"), "223.5.5.5:53")

	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 512)
	n, _, err := clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if n < 4 {
		t.Fatalf("reply is %d bytes, too short for a SOCKS5 UDP header", n)
	}

	// 用对端（tun2socks）读取时相同的帧格式解析：头中的地址就是它用来匹配应答的源地址。
	target, payload := parseUDPFrame(t, buf[:n])
	if target != "223.5.5.5:53" {
		t.Errorf("reply source = %s, want the client's target 223.5.5.5:53", target)
	}
	if got := string(payload); got != "answer" {
		t.Errorf("payload = %q, want %q", got, "answer")
	}
}
