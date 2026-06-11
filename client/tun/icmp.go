package tun

import (
	"context"
	"time"

	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type ICMPProxy interface {
	OpenICMPStream(ctx context.Context, target string, echoPayload []byte, method protocol.Method) (replyPayload []byte, err error)
}

type ICMPHandler struct {
	router *router.Router
	proxy  ICMPProxy
	method protocol.Method
}

func NewICMPHandler(rt *router.Router) *ICMPHandler {
	return &ICMPHandler{router: rt}
}

func (h *ICMPHandler) SetProxy(proxy ICMPProxy, method protocol.Method) {
	h.proxy = proxy
	h.method = method
}

func (h *ICMPHandler) HandlePacket(pkt adapter.Packet) bool {
	if h.router == nil {
		return false
	}

	id := pkt.ID()
	dstAddr := id.LocalAddress.String()

	rule := h.router.MatchHostRule(dstAddr)

	switch rule {
	case router.HostRuleDirect:
		return false
	case router.HostRuleBlock:
		log.Debug("[TUN-ICMP] blocked", "dst", dstAddr)
		return true
	case router.HostRuleProxy:
		return h.handleProxyICMP(pkt)
	default:
		return false
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

	payloadView := stack.PayloadSince(pkt.TransportHeader())
	payload := payloadView.AsSlice()

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

	replyPayload, err := h.proxy.OpenICMPStream(ctx, dstAddr.String(), payload, h.method)
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

	replyData := stack.PayloadSince(pkt.TransportHeader())
	defer replyData.Release()

	replyICMP := header.ICMPv4(replyData.AsSlice())
	replyICMP.SetType(header.ICMPv4EchoReply)
	replyICMP.SetCode(0)
	replyICMP.SetChecksum(0)
	replyICMP.SetChecksum(^checksum.Checksum(replyData.AsSlice(), 0))

	replyBuf := buffer.MakeWithView(replyData.Clone())
	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            replyBuf,
	})
	defer replyPkt.DecRef()

	sent := s.Stats().ICMP.V4.PacketsSent
	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.ICMPv4ProtocolNumber,
		TTL:      r.DefaultTTL(),
	}, replyPkt); err != nil {
		sent.Dropped.Increment()
		return
	}
	sent.EchoReply.Increment()
}

func (h *ICMPHandler) sendICMPv6Reply(s *stack.Stack, id stack.TransportEndpointID, pkt *stack.PacketBuffer, payload []byte) {
	_ = s
	_ = id
	_ = pkt
	_ = payload
}
