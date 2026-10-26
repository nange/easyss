package handler

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/nange/easyss/v3/util"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func TestLanHostOf(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"8.8.8.8", "8.8.8.8"},              // 裸 IP（IPConn.RemoteAddr）
		{"8.8.8.8:9", "8.8.8.8"},            // TCP/UDP 形式
		{"2001:db8::1", "2001:db8::1"},      // 裸 IPv6
		{"[2001:db8::1]:53", "2001:db8::1"}, // 带端口的 IPv6
		{"fe80::1%en0", "fe80::1"},          // 带 zone 的裸 IPv6
		{"[fe80::1%en0]:0", "fe80::1%en0"},  // 带端口和 zone 的 IPv6
		{"", ""},
	}
	for _, tt := range tests {
		if got := lanHostOf(tt.in); got != tt.want {
			t.Errorf("lanHostOf(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestLanHostOfSSRFGuard 固定拨号后的 SSRF 检查：从 IPConn 风格的裸地址提取出的主机
// 必须原样传给 util.IsLANIP，否则解析到 LAN 主机的 DNS 重绑定名称就会绕过防护。
func TestLanHostOfSSRFGuard(t *testing.T) {
	for _, lan := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "fe80::1"} {
		if !util.IsLANIP(lanHostOf(lan)) {
			t.Errorf("lan host %q must be rejected by the SSRF guard", lan)
		}
	}
	for _, pub := range []string{"8.8.8.8", "1.1.1.1:53", "2001:4860:4860::8888"} {
		if util.IsLANIP(lanHostOf(pub)) {
			t.Errorf("public host %q must pass the SSRF guard", pub)
		}
	}
}

// TestICMPFirstReadBufSize 守住常规 ping 只借小缓冲：回显应答的数据部分由请求决定，
// 按请求推导后只有大请求才触及 64KB 档。断言纯函数是因为真实 ICMP 需要 root 与可达目标。
func TestICMPFirstReadBufSize(t *testing.T) {
	tests := []struct {
		name    string
		payload int
		want    int
	}{
		// 常规 ping：8 字节 ICMP 头 + 56 字节数据 → 远小于最小档位，取最小档位。
		{"shell ping", 8 + 56, icmpMinReadBufSize},
		{"empty request", 4, icmpMinReadBufSize},
		// 恰好落在最小档位边界。
		{"exactly min", icmpMinReadBufSize - icmpIPHeaderReserve + 4, icmpMinReadBufSize},
		// 超过最小档位后按请求增长（数据部分 + IP 头预留）。
		{"grows with request", 8192 + 4, 8192 + icmpIPHeaderReserve},
		// 超过上限时钳制到单个 IP 报文的最大长度。
		{"clamped to ip max", 70000, icmpMaxReadBufSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := icmpFirstReadBufSize(make([]byte, tt.payload))
			if got != tt.want {
				t.Fatalf("icmpFirstReadBufSize(%d) = %d, want %d", tt.payload, got, tt.want)
			}
			if got < icmpMinReadBufSize || got > icmpMaxReadBufSize {
				t.Fatalf("size %d 超出 [%d, %d]", got, icmpMinReadBufSize, icmpMaxReadBufSize)
			}
		})
	}
}

// TestICMPExchangeRewritesEchoID 固定服务端对回显 ID 的唯一化：原始 socket 的应答由
// 内核按目标地址投递，客户端自选的 (ID, Seq) 在同目标并发时可能重复。服务端必须用自己
// 分配的 ID 匹配应答，再把客户端 ID 还原，否则同目标的两条会话会互相认领载荷。
func TestICMPExchangeRewritesEchoID(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close() //nolint:errcheck
		serverConn.Close() //nolint:errcheck
	})

	h := &icmpHandler{}
	h.dial.direct = func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	}

	const (
		sentID  = 0xFFFE // 计数器从 1 开始，本测试进程不会分配到它
		sentSeq = 7
	)
	payload := make([]byte, 4+len("client-payload"))
	binary.BigEndian.PutUint16(payload[0:2], sentID)
	binary.BigEndian.PutUint16(payload[2:4], sentSeq)
	copy(payload[4:], "client-payload")

	type outcome struct {
		reply []byte
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		reply, _, err := h.icmpExchange("1.1.1.1", payload)
		done <- outcome{reply: reply, err: err}
	}()

	reqBuf := make([]byte, 1500)
	n, err := serverConn.Read(reqBuf)
	if err != nil {
		t.Fatalf("read echo request: %v", err)
	}
	reqMsg, err := icmp.ParseMessage(1, reqBuf[:n])
	if err != nil {
		t.Fatalf("parse echo request: %v", err)
	}
	reqEcho, ok := reqMsg.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("echo request body = %T", reqMsg.Body)
	}
	if reqEcho.ID == sentID {
		t.Fatalf("server must rewrite the client-chosen echo id %#x", sentID)
	}
	if reqEcho.Seq != sentSeq {
		t.Fatalf("seq = %d, want %d", reqEcho.Seq, sentSeq)
	}

	writeReply := func(id int, data string) {
		t.Helper()
		reply, merr := (&icmp.Message{
			Type: ipv4.ICMPTypeEchoReply,
			Body: &icmp.Echo{ID: id, Seq: sentSeq, Data: []byte(data)},
		}).Marshal(nil)
		if merr != nil {
			t.Fatalf("marshal echo reply: %v", merr)
		}
		if _, werr := serverConn.Write(reply); werr != nil {
			t.Fatalf("write echo reply: %v", werr)
		}
	}

	// 同目标的另一条会话（客户端自选 ID 恰好相同）的应答先到，本会话不得认领。
	writeReply(sentID, "other-session")
	// 本会话的应答随后到达。
	writeReply(reqEcho.ID, "client-payload")

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("icmpExchange: %v", got.err)
		}
		if id := binary.BigEndian.Uint16(got.reply[0:2]); id != sentID {
			t.Fatalf("reply id = %#x, want the client id %#x", id, sentID)
		}
		if seq := binary.BigEndian.Uint16(got.reply[2:4]); seq != sentSeq {
			t.Fatalf("reply seq = %d, want %d", seq, sentSeq)
		}
		if data := string(got.reply[4:]); data != "client-payload" {
			t.Fatalf("reply payload = %q: another session's reply was accepted", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("icmpExchange did not return")
	}
}
