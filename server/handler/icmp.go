package handler

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util/bytespool"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// 以下常量都是 ICMP 协议本身的属性，不是可调参数。
const (
	// icmpExchangeDeadline 是一次性、无 context 的 ICMP 交换唯一的生命周期上限。
	icmpExchangeDeadline = 5 * time.Second

	// icmpMaxReadBufSize 是单个 IP 报文的最大长度（IPv4 总长度字段只有 16 位）。
	icmpMaxReadBufSize = 65535

	// icmpMinReadBufSize 是读取缓冲的起点：绝大多数 ICMP 是几十字节的普通 ping，
	// 只有确实读满时才升到上限，否则每次交换都要借出 64KB。
	icmpMinReadBufSize = 4 * 1024

	// icmpIPHeaderReserve 预留 Linux/Windows 原始 "ip4:icmp" socket 一并交给用户态的
	// IPv4 头（解析前剥掉），IPv4 头最长 60 字节。
	icmpIPHeaderReserve = 64
)

// icmpFirstReadBufSize 是纯函数，"小请求只借小缓冲"这条内存契约才能被直接单测：
// 真实 ICMP 交换需要 root 与外部可达目标，不适合做断言基础。
func icmpFirstReadBufSize(requestPayload []byte) int {
	size := len(requestPayload) - 4 + icmpIPHeaderReserve
	return min(max(size, icmpMinReadBufSize), icmpMaxReadBufSize)
}

type icmpHandler struct {
	dial dialer
}

// newICMPHandler 的出站超时与 TCP/UDP handler 共用同一个 Dial 值，零值已由 config.Timeouts.Normalize 派生。
func newICMPHandler(timeouts config.Timeouts) *icmpHandler {
	directDialer := outboundDialer(timeouts.Dial, 0)
	return &icmpHandler{
		dial: dialer{
			direct: func(ctx context.Context, network, target string) (net.Conn, error) {
				return dialOutbound(ctx, directDialer, network, target)
			},
		},
	}
}

// Handle 完成一次 ICMP 回显交换：读一个回显请求，以回显应答加 FIN 回复。签名与 TCP/UDP handler
// 不对称（没有 context 与 cancelRead）是刻意的：交换是自包含的，由自身的读取截止时间限定。
func (h *icmpHandler) Handle(dr *crypto.DecryptedReader, s2c shaper.Shaper, target string) streamResult {
	frame, done, err := nextClientFrame(dr)
	if err != nil {
		return streamResult{Err: err}
	}
	if done {
		return streamResult{}
	}

	replyPayload, remote, err := h.icmpExchange(target, frame.Payload)
	if err != nil {
		result := streamResult{Err: err}
		if result.needsRST() {
			sendRST(s2c)
		}
		return result
	}

	dataFrame := protocol.NewFrameDATA(replyPayload)
	finFrame := protocol.NewFrameFIN()
	_ = s2c.PushFrame(dataFrame)
	_ = s2c.PushFrame(finFrame)
	_ = s2c.Flush()
	return streamResult{Remote: remote, Bytes: int64(len(replyPayload))}
}

func (h *icmpHandler) icmpExchange(target string, payload []byte) (reply []byte, remote string, err error) {
	log.Debug("[ICMP] exchange", "target", target)

	if len(payload) < 4 {
		return nil, "", io.ErrUnexpectedEOF
	}

	isIPv6 := isIPv6Target(target)
	// 网络名必须写死地址族 + 协议号：IPv6 的 ICMPv6 是 58，而 "ip:icmp" 会让 Go 取到
	// /etc/protocols 里的 ipv4 "icmp"(1)，在 AF_INET6 原始 socket 上永远收不到回显应答。
	dialNet := "ip4:icmp"
	parseProto := 1
	if isIPv6 {
		dialNet = "ip6:ipv6-icmp"
		parseProto = 58
	}

	// 共享的 dialer 需要一个 context，而 ICMP 没有，拨号超时仍由 Dialer 限制。
	conn, connRemote, err := h.dial.dialTarget(context.Background(), dialNet, target)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close() //nolint:errcheck

	var echoType icmp.Type
	if isIPv6 {
		echoType = ipv6.ICMPTypeEchoRequest
	} else {
		echoType = ipv4.ICMPTypeEcho
	}

	sentID := int(binary.BigEndian.Uint16(payload[:2]))
	sentSeq := int(binary.BigEndian.Uint16(payload[2:4]))
	msg := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   sentID,
			Seq:  sentSeq,
			Data: payload[4:],
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return nil, "", err
	}

	if err := conn.SetDeadline(time.Now().Add(icmpExchangeDeadline)); err != nil {
		return nil, "", err
	}

	if _, err := conn.Write(wb); err != nil {
		return nil, "", err
	}

	rb := bytespool.Get(icmpFirstReadBufSize(payload))
	defer func() { bytespool.MustPut(rb) }()

	// 原始 ICMP socket 会收到送达本机的所有 ICMP 报文，并发流的应答 ID/Seq 会串台，
	// 因此持续读到截止时间并只认自己那一对；ICMP 错误报文永远不匹配，表现为超时。
	for {
		n, err := conn.Read(rb)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Debug("[ICMP] read timed out", "target", target)
			}
			return nil, "", err
		}

		// 读满即按可能截断处理（"大于缓冲"与"恰好等于缓冲"无法区分）。升到上限只让
		// 后续报文不再被截断——被截断的那一条救不回来，raw socket 已经消费掉它。
		if n == len(rb) && len(rb) < icmpMaxReadBufSize {
			bytespool.SwapIn(&rb, bytespool.Get(icmpMaxReadBufSize))
			continue
		}

		data := rb[:n]
		// Linux/Windows 的原始 "ip4:icmp" socket 附带 IPv4 头，macOS/BSD 已剥掉；不剥掉它，
		// IP 头会被当成 ICMP 类型（0x45 -> 69），回显应答永远识别不出来。
		if !isIPv6 && len(data) > 0 && data[0]>>4 == 4 {
			ihl := int(data[0]&0x0F) * 4
			if ihl >= 20 && ihl < len(data) {
				data = data[ihl:]
			}
		}

		rm, err := icmp.ParseMessage(parseProto, data)
		if err != nil {
			continue
		}

		var replyType icmp.Type
		if isIPv6 {
			replyType = ipv6.ICMPTypeEchoReply
		} else {
			replyType = ipv4.ICMPTypeEchoReply
		}
		if rm.Type != replyType {
			continue
		}

		body, ok := rm.Body.(*icmp.Echo)
		if !ok || body.ID != sentID || body.Seq != sentSeq {
			continue
		}
		result := make([]byte, 4+len(body.Data))
		binary.BigEndian.PutUint16(result[:2], uint16(body.ID))
		binary.BigEndian.PutUint16(result[2:4], uint16(body.Seq))
		copy(result[4:], body.Data)
		return result, connRemote, nil
	}
}

func isIPv6Target(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}
