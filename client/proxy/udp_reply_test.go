package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/txthinking/socks5"
)

// TestSendToClientFramesReplyFromClientTarget pins the invariant every DNS
// branch depends on: an answer is framed with the address the client sent its
// query to, never with the upstream this proxy resolved through. A transparent
// NAT in front (tun2socks) keys its UDP flows by that address in symmetric NAT
// mode and drops any datagram whose source differs from it, so a reply framed
// with the upstream made the query look unanswered — for every proxied query
// whose upstream (config.ProxyDNSServer, 8.8.8.8:53) differed from the
// resolver the client asked (e.g. the 223.5.5.5 configured for TUN mode).
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

	// The SOCKS5 side only touches srv.UDPConn here, so a bare server is
	// enough: no listener, handler or transport is involved.
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

	// Parse with the same framing the peer (tun2socks) reads: the address in
	// the header is the source it matches the reply against.
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
