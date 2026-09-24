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
	"github.com/txthinking/socks5"
)

// 本文件是 TCP DNS 拦截的前端：DNS over TCP 的帧编解码与连接循环。查询的分流
// 与解析由 dnsInterceptor 承担（见 dns_tcp.go），这里只负责读帧、写帧，以及
// 首条报文不是 DNS 查询时把连接交回按目标 IP 的普通分流。

// maxTCPDNSMessageLen 是 DNS over TCP 单条报文的最大长度。长度字段是 uint16，
// 理论上限 65535；这里再收紧一档，拒绝明显非 DNS 的畸形长度。
const maxTCPDNSMessageLen = 64 * 1024

// bufferedConn 让已经用 bufio.Reader 预读过的连接重新作为普通 net.Conn 使用：
// Read 先消费缓冲区，再落到底层连接。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// newBufferedConn 构造 bufferedConn；pending 是回退前已消耗的字节，会先于缓冲区的
// 其余内容被读出，保证回退中继不丢字节。
func newBufferedConn(c net.Conn, br *bufio.Reader, pending []byte) net.Conn {
	if len(pending) == 0 {
		return &bufferedConn{Conn: c, r: br}
	}
	return &bufferedConn{Conn: c, r: bufio.NewReader(io.MultiReader(bytes.NewReader(pending), br))}
}

// readFirstTCPDNS 从流中读取一条 DNS over TCP 报文（2 字节长度前缀 + DNS 报文），
// 并在失败时返回已消耗的字节：首条报文可能只是恰好落在 53 端口上的非 DNS 流量，
// 回退中继必须把这些字节原样还给目标。
//
// touch 在长度前缀读完后调用一次，让调用方按读取进度续期读截止时间：否则整条
// 报文（最长 64KB）会被塞进一个固定的首读窗口，慢速滴水即可长期占住 goroutine。
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

// readTCPDNSMessage 读取后续（可丢弃）的一条 DNS over TCP 报文，语义与
// readFirstTCPDNS 相同但不关心已消耗字节，由后者兜住读取逻辑。
func readTCPDNSMessage(br *bufio.Reader, touch func()) (*dns.Msg, error) {
	msg, _, err := readFirstTCPDNS(br, touch)
	return msg, err
}

// writeTCPDNSMessage 以 DNS over TCP 帧格式写出一条应答。
func writeTCPDNSMessage(w io.Writer, msg *dns.Msg) error {
	data, err := msg.Pack()
	if err != nil {
		return err
	}
	// 长度字段是 uint16：超出会静默回绕。上游为 UDP 交换时实际不可达，
	// 这里做防御性拒绝。
	if len(data) > 0xffff {
		return fmt.Errorf("dns tcp message too large: %d bytes", len(data))
	}
	buf := make([]byte, 0, len(data)+2)
	buf = append(buf, byte(len(data)>>8), byte(len(data)))
	buf = append(buf, data...)
	_, err = w.Write(buf)
	return err
}

// touchReadDeadline 返回一个把连接读截止时间续期 timeout 的回调，供读帧函数
// 在读取过程中按进度调用。续期失败无从报告（读帧函数只返回协议错误），因此
// 忽略；真正的连接错误会在随后的 Read 上暴露。
func touchReadDeadline(c net.Conn, timeout time.Duration) func() {
	return func() { _ = c.SetReadDeadline(time.Now().Add(timeout)) }
}

// handleTCPDNS 拦截发往 53 端口的 TCP 连接，按查询域名分流应答
// （与 UDP 的 handleUDPQuery 行为一致）。首条报文无法解析为 DNS 查询时，
// 回退到按目标 IP 的普通中继（已读字节还给流）。
func (s *Socks5Server) handleTCPDNS(c net.Conn, r *socks5.Request, target, host string) error {
	br := bufio.NewReader(c)

	// 扫雷式首读：只要首条报文没被确认为 DNS 查询，最终都会走按目标 IP 的普通
	// 中继，因此这里只受一个宽限期约束——连接建立后完全不发数据的客户端不应挂住
	// 本 goroutine。该窗口在读到长度前缀后按进度续期，覆盖载荷读取；一旦确认是
	// DNS 查询，之后的空闲计时改由 queryIdle 承担。
	if err := c.SetReadDeadline(time.Now().Add(s.streamIdleTimeout)); err != nil {
		return err
	}
	touch := touchReadDeadline(c, s.streamIdleTimeout)

	first, consumed, err := readFirstTCPDNS(br, touch)
	if err != nil {
		if errors.Is(err, io.EOF) {
			// 客户端连上后立即关闭：无事可做。
			return nil
		}
		log.Debug("[TCP_DNS] first message unreadable, fallback to relay", "target", target, "err", err)
		return s.fallbackTCPDNS(c, br, consumed, r, target, host)
	}
	if !isDNSQueryMsg(first) {
		log.Debug("[TCP_DNS] first message is not a dns query, fallback to relay", "target", target)
		return s.fallbackTCPDNS(c, br, consumed, r, target, host)
	}

	// 是 DNS 查询：先回 SOCKS5 成功应答，再逐条处理。
	if err := writeSocksSuccessReply(c); err != nil {
		return err
	}

	sess := s.dns.newTCPSession(c.RemoteAddr())
	defer sess.close()

	msg := first
	for {
		resp, err := sess.resolve(msg, target)
		if err != nil {
			// 上游解析失败：回 SERVFAIL，连接继续，让客户端自行重试。
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
			// EOF/超时/对端关闭：连接结束。
			return nil
		}
		if !isDNSQueryMsg(msg) {
			return nil
		}
	}
}

// fallbackTCPDNS 在首条报文无法识别为 DNS 查询时，把连接交回按目标 IP 的
// 普通分流（已读字节通过 pending 还给流），并清除本路径设置的读截止时间。
func (s *Socks5Server) fallbackTCPDNS(c net.Conn, br *bufio.Reader, pending []byte, r *socks5.Request, target, host string) error {
	_ = c.SetReadDeadline(time.Time{})
	return s.routeTCP(newBufferedConn(c, br, pending), r, target, host)
}
