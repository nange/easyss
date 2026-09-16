package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/txthinking/socks5"
)

// TestSendToClientFramesReplyFromClientTarget 固定了每个 DNS 分支都依赖的不变式：
// 应答使用客户端发送查询时所用的地址组帧，绝不使用本代理解析到的上游地址。
// 前置的透明 NAT（tun2socks）在对称 NAT 模式下以该地址为 UDP 流建键，并丢弃任何
// 源地址与之不同的数据报，因此用上游地址组帧的应答会让查询看起来无人应答——
// 对每个上游（config.ProxyDNSServer，8.8.8.8:53）与客户端所询问的解析器
// （如 TUN 模式配置的 223.5.5.5）不同的代理查询都是如此。
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
	s.sendToClient(&socks5.Server{UDPConn: serverConn}, clientAddr, []byte("answer"), "223.5.5.5:53")

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
	d, err := socks5.NewDatagramFromBytes(buf[:n])
	if err != nil {
		t.Fatalf("parse reply datagram: %v", err)
	}
	if got := d.Address(); got != "223.5.5.5:53" {
		t.Errorf("reply source = %s, want the client's target 223.5.5.5:53", got)
	}
	if got := string(d.Data); got != "answer" {
		t.Errorf("payload = %q, want %q", got, "answer")
	}
}
