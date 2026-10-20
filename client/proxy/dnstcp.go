package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/log"
)

// 长度字段是 uint16（上限 65535），这里再收紧一档以拒绝明显非 DNS 的畸形长度。
const maxTCPDNSMessageLen = 64 * 1024

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// pending 是回退前已消耗的字节，先于缓冲区其余内容读出。
func newBufferedConn(c net.Conn, br *bufio.Reader, pending []byte) net.Conn {
	if len(pending) == 0 {
		return &bufferedConn{Conn: c, r: br}
	}
	return &bufferedConn{Conn: c, r: bufio.NewReader(io.MultiReader(bytes.NewReader(pending), br))}
}

// 失败时返回已消耗的字节：首条报文可能只是恰好落在 53 端口上的非 DNS 流量，回退中继必须把它
// 原样还给目标。touch 在读完长度前缀后调用一次，否则慢速滴水即可长期占住 goroutine。
func readFirstTCPDNS(br *bufio.Reader, touch func()) (msg *dns.Msg, consumed []byte, err error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		return nil, nil, err
	}
	consumed = append(consumed, lenBuf[:]...)
	length := int(lenBuf[0])<<8 | int(lenBuf[1])
	if length == 0 || length > maxTCPDNSMessageLen {
		return nil, consumed, fmt.Errorf("dns tcp message length %d out of range", length)
	}

	if touch != nil {
		touch()
	}
	data := make([]byte, length)
	n, err := io.ReadFull(br, data)
	consumed = append(consumed, data[:n]...)
	if err != nil {
		return nil, consumed, err
	}
	msg = &dns.Msg{}
	if err := msg.Unpack(data); err != nil {
		return nil, consumed, err
	}
	return msg, consumed, nil
}

func readTCPDNSMessage(br *bufio.Reader, touch func()) (*dns.Msg, error) {
	msg, _, err := readFirstTCPDNS(br, touch)
	return msg, err
}

func writeTCPDNSMessage(w io.Writer, msg *dns.Msg) error {
	data, err := msg.Pack()
	if err != nil {
		return err
	}
	// 长度字段是 uint16，超出会静默回绕，这里防御性拒绝。
	if len(data) > 0xffff {
		return fmt.Errorf("dns tcp message too large: %d bytes", len(data))
	}
	buf := make([]byte, 0, len(data)+2)
	buf = append(buf, byte(len(data)>>8), byte(len(data)))
	buf = append(buf, data...)
	_, err = w.Write(buf)
	return err
}

func touchReadDeadline(c net.Conn, timeout time.Duration) func() {
	return func() { _ = c.SetReadDeadline(time.Now().Add(timeout)) }
}

// 首条报文无法解析为 DNS 查询时回退到按目标 IP 的普通中继。成功应答必须在任何读取之前写出：
// RFC 1928 的客户端要等应答才发数据（curl、浏览器、tun2socks 都是如此），推迟则双方互等。
func (s *Socks5Server) handleTCPDNS(c net.Conn, target, host string) error {
	if err := writeSocksSuccessReply(c); err != nil {
		log.Error("[TCP_DNS] reply", "target", target, "err", err)
		return err
	}

	br := bufio.NewReader(c)

	// 首读只受一个宽限期约束：完全不发数据的客户端不该挂住本 goroutine；窗口在读到长度前缀后
	// 按进度续期，确认是 DNS 查询后改由 queryIdle 计时。
	if err := c.SetReadDeadline(time.Now().Add(s.streamIdleTimeout)); err != nil {
		return err
	}
	touch := touchReadDeadline(c, s.streamIdleTimeout)

	first, consumed, err := readFirstTCPDNS(br, touch)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		log.Debug("[TCP_DNS] first message unreadable, fallback to relay", "target", target, "err", err)
		return s.fallbackTCPDNS(c, br, consumed, target, host)
	}
	if !isDNSQueryMsg(first) {
		log.Debug("[TCP_DNS] first message is not a dns query, fallback to relay", "target", target)
		return s.fallbackTCPDNS(c, br, consumed, target, host)
	}

	sess := s.dns.newTCPSession(c.RemoteAddr())
	defer sess.close()

	msg := first
	for {
		resp, err := sess.resolve(msg, target)
		if err != nil {
			log.Warn("[TCP_DNS] resolve", "target", target, "err", err)
			resp = new(dns.Msg)
			resp.SetRcode(msg, dns.RcodeServerFailure)
		}
		if resp == nil {
			resp = new(dns.Msg)
			resp.SetRcode(msg, dns.RcodeServerFailure)
		}
		if err := writeTCPDNSMessage(c, resp); err != nil {
			return err
		}

		if err := c.SetReadDeadline(time.Now().Add(s.dns.queryIdle)); err != nil {
			return err
		}
		msg, err = readTCPDNSMessage(br, touchReadDeadline(c, s.dns.queryIdle))
		if err != nil {
			return nil
		}
		if !isDNSQueryMsg(msg) {
			return nil
		}
	}
}

// 已读字节经 pending 还给流；成功应答已由 handleTCPDNS 写出，因此以 replied=true 交回。
func (s *Socks5Server) fallbackTCPDNS(c net.Conn, br *bufio.Reader, pending []byte, target, host string) error {
	_ = c.SetReadDeadline(time.Time{})
	return s.routeTCPReplied(newBufferedConn(c, br, pending), target, host, true)
}
