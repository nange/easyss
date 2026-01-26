package easyss

import (
	"fmt"
	"net"
	"time"

	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (ss *Easyss) HandlePacket(p adapter.Packet) bool {
	pkt := p.Buffer()
	if pkt.NetworkProtocolNumber != ipv4.ProtocolNumber {
		log.Info("[ICMP] not ipv4 packet", "protocol", pkt.NetworkProtocolNumber)
		return false
	}
	if h := header.ICMPv4(pkt.TransportHeader().Slice()); h.Type() != header.ICMPv4Echo {
		return false
	}

	ipHdr := header.IPv4(pkt.NetworkHeader().Slice())

	dest := ipHdr.DestinationAddress().To4()

	log.Info("[ICMP] echo request", "sourceAddr", ipHdr.SourceAddress(), "dest", dest, "id", p.ID())

	var icmpHdr header.ICMPv4
	var icmpErr error
	if dest.Len() == 4 {
		dest4 := dest.As4()
		addr := fmt.Sprintf("%d.%d.%d.%d", dest4[0], dest4[1], dest4[2], dest4[3])

		reqData := stack.PayloadSince(pkt.TransportHeader())
		defer reqData.Release()

		// TODO: 添加直连ping功能，并且探索返回错误ping消息功能
		icmpHdr, icmpErr = ss.proxyICMPEcho(addr, reqData.AsSlice())
		if icmpErr != nil {
			log.Warn("[ICMP] proxy echo request to remote failed", "err", icmpErr)
			return false
		}
	}

	if icmpHdr != nil {
		echoReply(p.Stack(), pkt, icmpHdr.Type(), icmpHdr.Code())
	}

	return true

}

func (ss *Easyss) proxyICMPEcho(addr string, data []byte) (header.ICMPv4, error) {
	csStream, err := ss.handShakeWithRemote(addr, cipherstream.FlagICMP)
	if err != nil {
		log.Warn("[ICMP] handshake with remote failed", "err", err)
		return nil, err
	}
	defer func() {
		if ss.IsNativeOutboundProto() {
			go tryReuseInICMP(csStream, ss.Timeout())
		} else {
			csStream.(*cipherstream.CipherStream).MarkConnUnusable()
			_ = csStream.Close()
		}
	}()

	_ = csStream.SetReadDeadline(time.Now().Add(ss.PingTimeout()))
	_, err = csStream.Write(data)
	if err != nil {
		log.Warn("[ICMP] write echo request to remote", "err", err)
		return nil, err
	}

	frame, err := csStream.(*cipherstream.CipherStream).ReadFrame()
	if err != nil {
		log.Warn("[ICMP] read echo reply from remote", "err", err)
		return nil, err
	}

	data = frame.RawDataPayload()

	return header.ICMPv4(data), nil
}

func echoReply(s *stack.Stack, pkt *stack.PacketBuffer, icmpType header.ICMPv4Type, icmpCode header.ICMPv4Code) error {
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
		return fmt.Errorf("find route to %s failed, err: %s", ipHdr.SourceAddress(), err.String())
	}
	defer r.Release()

	replyData := stack.PayloadSince(pkt.TransportHeader())
	defer replyData.Release()

	replyICMPHdr := header.ICMPv4(replyData.AsSlice())
	replyICMPHdr.SetType(icmpType)
	replyICMPHdr.SetCode(icmpCode) // RFC 792: EchoReply must have Code=0.
	replyICMPHdr.SetChecksum(0)
	replyICMPHdr.SetChecksum(^checksum.Checksum(replyData.AsSlice(), 0))

	replyBuf := buffer.MakeWithView(replyData.Clone())
	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            replyBuf,
	})
	defer replyPkt.DecRef()

	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.ICMPv4ProtocolNumber,
		TTL:      r.DefaultTTL(),
	}, replyPkt); err != nil {
		return fmt.Errorf("write echo reply to remote failed, err: %s", err.String())
	}

	return nil
}

func tryReuseInICMP(cipher net.Conn, timeout time.Duration) {
	defer cipher.Close()

	err := tryReuseInClient(cipher, timeout)
	if err != nil {
		log.Warn("[ICMP] underlying proxy connection is unhealthy, need close it", "err", err)
		cipher.(*cipherstream.CipherStream).MarkConnUnusable()
	} else {
		log.Debug("[ICMP] underlying proxy connection is healthy, so reuse it")
	}
}
