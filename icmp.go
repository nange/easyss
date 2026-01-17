package easyss

import (
	"time"

	"github.com/nange/easyss/v2/log"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (ss *Easyss) handleICMP(s *stack.Stack) func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
	return func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		if pkt.NetworkProtocolNumber != ipv4.ProtocolNumber {
			log.Info("[ICMP] not ipv4 packet", "protocol", pkt.NetworkProtocolNumber)
			return false
		}
		if h := header.ICMPv4(pkt.TransportHeader().Slice()); h.Type() != header.ICMPv4Echo {
			return false
		}
		time.Sleep(150 * time.Millisecond)
		ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
		localAddressBroadcast := pkt.NetworkPacketInfo.LocalAddressBroadcast

		// As per RFC 1122 section 3.2.1.3, when a host sends any datagram, the IP
		// source address MUST be one of its own IP addresses (but not a broadcast
		// or multicast address).
		localAddr := ipHdr.DestinationAddress()
		if localAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
			localAddr = tcpip.Address{}
		}

		r, err := s.FindRoute(pkt.NICID, localAddr, ipHdr.SourceAddress(), ipv4.ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			// If we cannot find a route to the destination, silently drop the packet.
			return false
		}
		defer r.Release()

		// TODO: 添加代理Ping逻辑

		replyData := stack.PayloadSince(pkt.TransportHeader())
		defer replyData.Release()

		replyICMPHdr := header.ICMPv4(replyData.AsSlice())
		replyICMPHdr.SetType(header.ICMPv4EchoReply)
		replyICMPHdr.SetCode(0) // RFC 792: EchoReply must have Code=0.
		replyICMPHdr.SetChecksum(0)
		replyICMPHdr.SetChecksum(^checksum.Checksum(replyData.AsSlice(), 0))

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
			return false
		}
		sent.EchoReply.Increment()
		return true
	}

}
