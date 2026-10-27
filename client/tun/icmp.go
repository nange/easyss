package tun

import (
	"context"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/bytespool"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type ICMPProxy interface {
	OpenICMPStream(ctx context.Context, target string, echoPayload []byte, method protocol.Method) (replyPayload []byte, err error)
}

// ICMPAction 是一次 ICMP echo 的分流动作。Windows helper 没有主进程的 router，分类
// 通过主进程的 /icmp/classify 端点完成，但后续动作与本进程内完全一致。
type ICMPAction uint8

const (
	ICMPActionDirect ICMPAction = iota
	ICMPActionBlock
	ICMPActionProxy
	ICMPActionDrop
)

// ICMPClassifier 返回目标地址的分流动作；icmpType 只用于日志。
type ICMPClassifier func(dst string, icmpType uint8) (ICMPAction, error)

type ICMPHandler struct {
	classify ICMPClassifier
	proxy    ICMPProxy
	method   protocol.Method
}

func NewICMPHandler(rt *router.Router) *ICMPHandler {
	if rt == nil {
		return &ICMPHandler{}
	}
	return &ICMPHandler{classify: ICMPClassifier(func(dst string, _ uint8) (ICMPAction, error) {
		// IPv6 策略门禁属于共享分类的一部分：当 ipv6_rule 禁用 IPv6 时，发往
		// 字面 IPv6 地址的 ICMP echo 必须以与 SOCKS5/HTTP 路径相同的条件被拒绝。
		cls := rt.ClassifyHost(dst)
		if cls.IPV6Rejected {
			return ICMPActionBlock, nil
		}
		switch cls.Rule {
		case router.HostRuleDirect:
			return ICMPActionDirect, nil
		case router.HostRuleBlock:
			return ICMPActionBlock, nil
		case router.HostRuleProxy:
			return ICMPActionProxy, nil
		default:
			return ICMPActionDrop, nil
		}
	})}
}

// NewICMPHandlerWithClassifier 供提权 helper 使用：分类来自主进程，代理仍由本进程的
// proxy 实现完成。proxy 用 SetProxy 注入，保持与 NewICMPHandler 相同的调用顺序。
func NewICMPHandlerWithClassifier(classify func(dst string) (ICMPAction, error)) *ICMPHandler {
	if classify == nil {
		return &ICMPHandler{}
	}
	return &ICMPHandler{classify: ICMPClassifier(func(dst string, _ uint8) (ICMPAction, error) {
		return classify(dst)
	})}
}

func (h *ICMPHandler) SetProxy(proxy ICMPProxy, method protocol.Method) {
	h.proxy = proxy
	h.method = method
}

func (h *ICMPHandler) HandlePacket(pkt adapter.Packet) bool {
	if h.classify == nil {
		return false
	}

	id := pkt.ID()
	dstAddr := id.LocalAddress.String()

	// 只有 echo 请求才值得记 INFO：其他类型永远不会被代理，tun2socks 的默认 forwarder
	// 反正会丢弃，记 INFO 只会在局域网网关每秒探测本机时刷屏。
	icmpType, echoRequest := icmpEchoRequest(pkt)
	if !echoRequest {
		log.Debug("[ICMP_DROP]", "dst", dstAddr, "type", icmpType, "reason", "non-echo")
		return false
	}

	action, err := h.classify(dstAddr, icmpType)
	if err != nil {
		// 不能落到 tun2socks 的默认 forwarder：它会给 IPv4 echo 伪造 echo reply，一次
		// 根本没发出去的 ping 会显示成功。分类失败一律消费掉，并留 Warn（默认级别可见）。
		log.Warn("[ICMP_DROP]", "dst", dstAddr, "type", icmpType, "reason", "classify", "err", err)
		return true
	}

	switch action {
	case ICMPActionDirect:
		log.Info("[ICMP_DIRECT]", "dst", dstAddr, "type", icmpType)
		return false
	case ICMPActionBlock:
		log.Info("[ICMP_BLOCK]", "dst", dstAddr, "type", icmpType)
		return true
	case ICMPActionProxy:
		log.Info("[ICMP_PROXY]", "dst", dstAddr, "type", icmpType)
		return h.handleProxyICMP(pkt)
	default:
		log.Debug("[ICMP_DROP]", "dst", dstAddr, "type", icmpType, "reason", "no-rule")
		return false
	}
}

// 报告 pkt 是否为 ICMPv4/ICMPv6 echo 请求——本 handler 唯一能路由或代理的 ICMP 报文——
// 并返回类型用于日志；短到装不下 ICMP 头的报文一律视为非 echo。
func icmpEchoRequest(pkt adapter.Packet) (icmpType uint8, ok bool) {
	buf := pkt.Buffer()
	if buf == nil {
		return 0, false
	}

	transHdr := buf.TransportHeader().Slice()
	switch buf.NetworkProtocolNumber {
	case ipv4.ProtocolNumber:
		if len(transHdr) < header.ICMPv4MinimumSize {
			return 0, false
		}
		t := header.ICMPv4(transHdr).Type()
		return uint8(t), t == header.ICMPv4Echo
	case header.IPv6ProtocolNumber:
		if len(transHdr) < header.ICMPv6HeaderSize {
			return 0, false
		}
		t := header.ICMPv6(transHdr).Type()
		return uint8(t), t == header.ICMPv6EchoRequest
	default:
		return 0, false
	}
}

func (h *ICMPHandler) handleProxyICMP(pkt adapter.Packet) bool {
	if h.proxy == nil {
		log.Debug("[TUN-ICMP] proxy not configured, falling back to direct")
		return false
	}

	buf := pkt.Buffer()
	if buf == nil {
		return false
	}

	netProto := buf.NetworkProtocolNumber
	if netProto != ipv4.ProtocolNumber && netProto != header.IPv6ProtocolNumber {
		return false
	}

	netHdrSlice := buf.NetworkHeader().Slice()
	transHdrSlice := buf.TransportHeader().Slice()
	if len(netHdrSlice) == 0 || len(transHdrSlice) == 0 {
		return false
	}

	if netProto == ipv4.ProtocolNumber {
		icmpHdr := header.ICMPv4(transHdrSlice)
		if icmpHdr.Type() != header.ICMPv4Echo {
			return false
		}
	} else {
		icmpHdr := header.ICMPv6(transHdrSlice)
		if icmpHdr.Type() != header.ICMPv6EchoRequest {
			return false
		}
	}

	cloned := buf.Clone()
	clonedID := pkt.ID()
	clonedStack := pkt.Stack()

	go h.processProxyICMP(clonedStack, clonedID, cloned)

	return true
}

func (h *ICMPHandler) processProxyICMP(s *stack.Stack, id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	defer pkt.DecRef()

	netProto := pkt.NetworkProtocolNumber

	// PayloadSince 返回完整的 ICMP 报文，包含头部（type+code+checksum+id+seq+data）。
	// 服务端只需要 echo 体（id+seq+data），因此去掉开头的 4 字节（type+code+checksum）。
	payloadView := stack.PayloadSince(pkt.TransportHeader())
	fullICMP := payloadView.AsSlice()

	var minSize int
	if netProto == ipv4.ProtocolNumber {
		minSize = header.ICMPv4MinimumSize
	} else {
		minSize = header.ICMPv6EchoMinimumSize
	}
	if len(fullICMP) < minSize {
		payloadView.Release()
		return
	}

	echoBody := bytespool.Get(len(fullICMP) - 4)
	copy(echoBody, fullICMP[4:])
	payloadView.Release()
	defer bytespool.MustPut(echoBody)

	var dstAddr tcpip.Address
	if netProto == ipv4.ProtocolNumber {
		ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
		dstAddr = ipHdr.DestinationAddress()
	} else {
		ipHdr := header.IPv6(pkt.NetworkHeader().Slice())
		dstAddr = ipHdr.DestinationAddress()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	replyPayload, err := h.proxy.OpenICMPStream(ctx, dstAddr.String(), echoBody, h.method)
	if err != nil {
		log.Debug("[TUN-ICMP] proxy icmp failed", "dst", dstAddr.String(), "err", err)
		return
	}

	if replyPayload == nil {
		return
	}

	if netProto == ipv4.ProtocolNumber {
		h.sendICMPv4Reply(s, id, pkt, replyPayload)
	} else {
		h.sendICMPv6Reply(s, id, pkt, replyPayload)
	}
}

func (h *ICMPHandler) sendICMPv4Reply(s *stack.Stack, id stack.TransportEndpointID, pkt *stack.PacketBuffer, payload []byte) {
	ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
	localAddressBroadcast := pkt.NetworkPacketInfo.LocalAddressBroadcast

	localAddr := ipHdr.DestinationAddress()
	if localAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
		localAddr = tcpip.Address{}
	}

	r, err := s.FindRoute(pkt.NICID, localAddr, ipHdr.SourceAddress(), ipv4.ProtocolNumber, false)
	if err != nil {
		log.Debug("[TUN-ICMP] find route failed", "err", err)
		return
	}
	defer r.Release()

	const icmpV4HdrSize = 4
	replyLen := icmpV4HdrSize + len(payload)
	replyData := buffer.NewViewWithData(make([]byte, replyLen))
	replySlice := replyData.AsSlice()

	copy(replySlice[icmpV4HdrSize:], payload)

	replyICMP := header.ICMPv4(replySlice)
	replyICMP.SetType(header.ICMPv4EchoReply)
	replyICMP.SetCode(0)
	replyICMP.SetChecksum(0)
	replyICMP.SetChecksum(^checksum.Checksum(replySlice, 0))

	replyBuf := buffer.MakeWithView(replyData)
	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            replyBuf,
	})
	defer replyPkt.DecRef()

	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.ICMPv4ProtocolNumber,
		TTL:      r.DefaultTTL(),
	}, replyPkt); err != nil {
		log.Debug("[TUN-ICMP] write ipv4 reply failed", "err", err)
	}
}

func (h *ICMPHandler) sendICMPv6Reply(s *stack.Stack, id stack.TransportEndpointID, pkt *stack.PacketBuffer, payload []byte) {
	ipv6Hdr := header.IPv6(pkt.NetworkHeader().Slice())

	localAddr := ipv6Hdr.DestinationAddress()
	remoteAddr := ipv6Hdr.SourceAddress()

	if header.IsV6MulticastAddress(localAddr) {
		return
	}

	r, err := s.FindRoute(pkt.NICID, localAddr, remoteAddr, ipv6.ProtocolNumber, false)
	if err != nil {
		log.Debug("[TUN-ICMP] find ipv6 route failed", "err", err)
		return
	}
	defer r.Release()

	replyLen := header.ICMPv6HeaderSize + len(payload)
	replyData := buffer.NewViewWithData(make([]byte, replyLen))

	icmpHdr := header.ICMPv6(replyData.AsSlice()[:header.ICMPv6HeaderSize])
	icmpHdr.SetType(header.ICMPv6EchoReply)
	icmpHdr.SetCode(0)

	copy(replyData.AsSlice()[header.ICMPv6HeaderSize:], payload)

	payloadCsum := checksum.Checksum(payload, 0)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHdr,
		Src:         localAddr,
		Dst:         remoteAddr,
		PayloadCsum: payloadCsum,
		PayloadLen:  len(payload),
	}))

	replyBuf := buffer.MakeWithView(replyData)
	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            replyBuf,
	})
	defer replyPkt.DecRef()

	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.ICMPv6ProtocolNumber,
		TTL:      r.DefaultTTL(),
	}, replyPkt); err != nil {
		log.Debug("[TUN-ICMP] write ipv6 reply failed", "err", err)
	}
}
