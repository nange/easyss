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

type icmpHandler struct {
	dial dialer
}

// newICMPHandler 创建一个 icmpHandler。出站 ICMP 拨号超时通过
// config.DialTimeout 派生（base/3，限制在 [3s, 15s]），与 TCP/UDP handler
// 的拨号共用同一套派生。
func newICMPHandler(timeout time.Duration) *icmpHandler {
	if timeout <= 0 {
		timeout = time.Duration(config.DefaultTimeout) * time.Second
	}
	dialTimeout := config.DialTimeout(timeout)
	return &icmpHandler{
		dial: dialer{
			direct: func(ctx context.Context, network, target string) (net.Conn, error) {
				d := &hostDialer{timeout: dialTimeout}
				return dialOutbound(ctx, d, network, target, preferredOrNone(ctx))
			},
		},
	}
}

// Handle 在每个流上完成一次 ICMP 回显交换：读取客户端的回显请求
// （DATA 帧，跳过 PADDING/COVER），执行交换，并以回显应答加 FIN 回复。
// 与 TCP/UDP handler 不同，它不携带 context 也没有 cancelRead：
// 交换是自包含的，由自身的读取截止时间限定，流在应答之后即结束。
func (h *icmpHandler) Handle(dr *crypto.DecryptedReader, s2c shaper.Shaper, target string) error {
	frame, done, err := nextClientFrame(dr)
	if err != nil {
		return err
	}
	if done {
		return nil
	}

	replyPayload, err := h.icmpExchange(target, frame.Payload)
	if err != nil {
		sendRST(s2c)
		return err
	}

	dataFrame := protocol.NewFrameDATA(replyPayload)
	finFrame := protocol.NewFrameFIN()
	_ = s2c.PushFrame(dataFrame)
	_ = s2c.PushFrame(finFrame)
	_ = s2c.Flush()
	return nil
}

func (h *icmpHandler) icmpExchange(target string, payload []byte) ([]byte, error) {
	log.Debug("[ICMP] exchange", "target", target)

	if len(payload) < 4 {
		return nil, io.ErrUnexpectedEOF
	}

	isIPv6 := isIPv6Target(target)
	// 网络名只给出协议，地址族由 dialOutbound 按目标字面量（或域名解析结果）
	// 与 ctx 中的客户端族偏好决定，因此这里不再分别写死 ip4:icmp / ip6:ipv6-icmp。
	dialNet := "ip:icmp"
	parseProto := 1
	if isIPv6 {
		parseProto = 58
	}

	// 共享的 dialer 需要一个 context；ICMP 没有（见 Handle），因此使用
	// background context。拨号超时仍然限制拨号本身，
	// 拨号后的 SSRF 防护在 dialTarget 内部执行。
	conn, _, err := h.dial.dialTarget(context.Background(), dialNet, target)
	if err != nil {
		log.Error("[ICMP] dial target failed", "target", target, "err", err)
		return nil, err
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
		return nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(wb); err != nil {
		log.Error("[ICMP] write failed", "target", target, "err", err)
		return nil, err
	}

	rb := bytespool.Get(65535)
	defer bytespool.MustPut(rb)

	// 原始 ICMP socket 会收到送达本机的所有匹配 ICMP 报文，而不只是本 socket
	// 自己请求的应答：并发访问同一目标的流可能产生 ID/Seq 属于其他流的应答。
	// 持续读取直到截止时间，忽略 ID/Seq 与我们所发送不匹配的报文。ICMP 错误
	// 报文（目标不可达、超时）永远不会匹配，因此它们会表现为超时错误，
	// 而不会被误报为成功应答。
	for {
		n, err := conn.Read(rb)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Debug("[ICMP] read timed out", "target", target)
			} else {
				log.Error("[ICMP] read failed", "target", target, "err", err)
			}
			return nil, err
		}

		data := rb[:n]
		// 在 Linux（和 Windows）上，原始 "ip4:icmp" socket 返回的 ICMP 载荷前
		// 会附带 IPv4 头，而 macOS/BSD 的原始 socket 已经剥掉它。如果第一个
		// 半字节看起来像 IPv4 头（版本 4），在把载荷交给 icmp.ParseMessage 之前
		// 先剥掉它，否则 IP 头会被误解析为 ICMP 类型（如 0x45 -> type 69），
		// 回显应答永远无法识别，从而在主服务器平台上悄悄破坏 ICMP 功能。
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
		return result, nil
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
