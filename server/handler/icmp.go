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

// icmpHandler 的常量。它们都是该协议本身的属性，不是可调参数，因此集中在此
// 并注释来源，而不是散落在交换逻辑里。
const (
	// icmpExchangeDeadline 限定一次回显请求的发送与应答等待。ICMP 交换是
	// 一次性、无 context 的，这个截止时间就是它唯一的生命周期上限。
	icmpExchangeDeadline = 5 * time.Second

	// icmpMaxReadBufSize 是回显应答读取缓冲的上限：单个 IP 报文的最大长度
	// （IPv4 总长度字段只有 16 位），因此足够容纳任何可读到的应答。
	icmpMaxReadBufSize = 65535

	// icmpMinReadBufSize 是回显应答读取缓冲的起点。回显应答的数据部分由请求
	// 决定（服务端回显 payload[4:]），而 VPS 上绝大多数 ICMP 是一次常规 ping
	// 或探活，因此从最小档位起步，只有"确实读满"时才升到上限——否则每次交换
	// 都要借出一整块 64KB 缓冲，而它只承载几十字节。
	icmpMinReadBufSize = 4 * 1024

	// icmpIPHeaderReserve 预留给链路层之下可能附带的 IP 头。Linux/Windows 的
	// 原始 "ip4:icmp" socket 会把 IPv4 头一并交给用户态（解析前已被剥掉，
	// 见 icmpExchange），IPv4 头最长 60 字节，这里取够。
	icmpIPHeaderReserve = 64
)

// icmpFirstReadBufSize 返回首次读取使用的缓冲大小：请求载荷加上可能的 IP 头，
// 再钳制到 [icmpMinReadBufSize, icmpMaxReadBufSize]。
//
// 它是纯函数，因此"小请求只借小缓冲"这条内存契约可以被直接单测——真实 ICMP
// 交换需要 root 与外部可达目标，不适合做断言基础。
func icmpFirstReadBufSize(requestPayload []byte) int {
	size := len(requestPayload) - 4 + icmpIPHeaderReserve
	return min(max(size, icmpMinReadBufSize), icmpMaxReadBufSize)
}

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
	directDialer := outboundDialer(dialTimeout, 0)
	return &icmpHandler{
		dial: dialer{
			direct: func(ctx context.Context, network, target string) (net.Conn, error) {
				return dialOutbound(ctx, directDialer, network, target)
			},
		},
	}
}

// Handle 在每个流上完成一次 ICMP 回显交换：读取客户端的回显请求
// （DATA 帧，跳过 PADDING/COVER），执行交换，并以回显应答加 FIN 回复。
// 与 TCP/UDP handler 不同，它不携带 context 也没有 cancelRead：
// 交换是自包含的，由自身的读取截止时间限定，流在应答之后即结束。
// 这处签名不对称是刻意的：把一次性回显交换硬塞进带 ctx/cancel 的流式接口
// 只会引入永远为空的参数。返回结构化结果（字节数与远端地址）供统一日志出口使用。
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
	// 原始 socket 的网络名必须写死地址族 + 协议号：IPv6 的 ICMPv6 是协议号 58，
	// 而 "ip:icmp" 会让 Go 取到 /etc/protocols 里的 ipv4 "icmp"(1)，在 AF_INET6
	// 原始 socket 上永远收不到回显应答。ICMP 拨号也不携带 context（见 Handle），
	// 因此它不参与出站地址族偏好。
	dialNet := "ip4:icmp"
	parseProto := 1
	if isIPv6 {
		dialNet = "ip6:ipv6-icmp"
		parseProto = 58
	}

	// 共享的 dialer 需要一个 context；ICMP 没有（见 Handle），因此使用
	// background context。拨号超时仍然限制拨号本身，
	// 拨号后的 SSRF 防护在 dialTarget 内部执行。
	conn, connRemote, err := h.dial.dialTarget(context.Background(), dialNet, target)
	if err != nil {
		log.Error("[ICMP] dial target failed", "target", target, "err", err)
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
		log.Error("[ICMP] write failed", "target", target, "err", err)
		return nil, "", err
	}

	rb := bytespool.Get(icmpFirstReadBufSize(payload))
	defer func() { bytespool.MustPut(rb) }()

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
			return nil, "", err
		}

		// 读满即可能被截断（"大于缓冲"与"恰好等于缓冲"无法区分，报文长度分布
		// 连续，因此按可能截断处理）。此时升到上限换一块大缓冲重读一次：
		// 缓冲从最小档位起步是为了常规 ping 不占 64KB，而不是为了在小报文上
		// 保持小缓冲。只升一次；到上限后再读满就无法再分辨，与改动前一致。
		if n == len(rb) && len(rb) < icmpMaxReadBufSize {
			bigger := bytespool.Get(icmpMaxReadBufSize)
			bytespool.SwapIn(bigger, rb[:0])
			rb = bigger
			continue
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
