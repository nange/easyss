package easyss

import (
	"fmt"
	"net"
	"time"

	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util"
	"github.com/nange/easyss/v2/util/bytespool"
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
		return false
	}
	ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
	if tcpip.TransportProtocolNumber(ipHdr.Protocol()) != header.ICMPv4ProtocolNumber {
		return false
	}
	if h := header.ICMPv4(pkt.TransportHeader().Slice()); h.Type() != header.ICMPv4Echo {
		return false
	}

	// Extract necessary info for async processing
	nicID := pkt.NICID
	src := ipHdr.SourceAddress()
	dst := ipHdr.DestinationAddress()
	localAddressBroadcast := pkt.NetworkPacketInfo.LocalAddressBroadcast

	reqDataView := stack.PayloadSince(pkt.TransportHeader())
	payload := append([]byte(nil), reqDataView.AsSlice()...)
	reqDataView.Release()

	// We also need the stack to send reply
	s := p.Stack()

	// Create a goroutine to avoid blocking the tun2socks engine
	go func() {
		dest := dst.To4()
		v4Type := header.ICMPv4EchoReply
		v4Code := header.ICMPv4NetUnreachable

		if dest.Len() == 4 {
			dest4 := dest.As4()
			host := fmt.Sprintf("%d.%d.%d.%d", dest4[0], dest4[1], dest4[2], dest4[3])

			rule := ss.MatchHostRule(host)
			var icmpHdr header.ICMPv4
			var icmpErr error

			switch rule {
			case HostRuleProxy:
				icmpHdr, icmpErr = ss.proxyICMPEcho(host, payload)
				if icmpErr != nil {
					log.Warn("[ICMP] proxy echo request to remote failed", "err", icmpErr)
				}
			case HostRuleDirect:
				icmpHdr, icmpErr = ss.directICMPEcho(host, payload)
				if icmpErr != nil {
					log.Warn("[ICMP] direct echo request to host failed", "err", icmpErr)
				}
			}

			if icmpErr == nil && icmpHdr != nil {
				v4Type = icmpHdr.Type()
				v4Code = icmpHdr.Code()
			}
		}

		if err := sendEchoReply(s, nicID, src, dst, localAddressBroadcast, payload, v4Type, v4Code); err != nil {
			log.Warn("[ICMP] echo reply failed", "err", err)
		}
	}()

	return true

}

func (ss *Easyss) directICMPEcho(host string, data []byte) (header.ICMPv4, error) {
	log.Info("[ICMP] direct echo request", "host", host)

	localIP, err := util.GetInterfaceIP(ss.LocalDevice())
	if err != nil {
		log.Error("[ICMP] get interface ip failed", "err", err)
		return nil, err
	}

	pc, err := ss.directDialer.ListenPacket("ip4:icmp", localIP)
	if err != nil {
		log.Error("[ICMP] listen icmp packet failed", "err", err)
		return nil, err
	}
	defer func() {
		_ = pc.Close()
	}()

	if err := pc.SetDeadline(time.Now().Add(ss.ICMPTimeout())); err != nil {
		log.Error("[ICMP] set deadline failed", "err", err)
		return nil, err
	}

	_, err = pc.WriteTo(data, &net.IPAddr{IP: net.ParseIP(host)})
	if err != nil {
		log.Error("[ICMP] write icmp packet failed", "err", err)
		return nil, err
	}

	buf := bytespool.Get(1024)
	defer bytespool.MustPut(buf)

	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		log.Error("[ICMP] read icmp packet failed", "err", err)
		return nil, err
	}

	return header.ICMPv4(buf[:n]), nil
}

func (ss *Easyss) proxyICMPEcho(host string, data []byte) (header.ICMPv4, error) {
	log.Info("[ICMP] proxy echo request", "host", host)

	csStream, err := ss.handShakeWithRemote(host, cipherstream.FlagICMP)
	if err != nil {
		log.Error("[ICMP] handshake with remote failed", "err", err)
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

	_ = csStream.SetDeadline(time.Now().Add(ss.ICMPTimeout()))
	_, err = csStream.Write(data)
	if err != nil {
		log.Error("[ICMP] write echo request to remote", "err", err)
		return nil, err
	}

	frame, err := csStream.(*cipherstream.CipherStream).ReadFrame()
	if err != nil {
		log.Error("[ICMP] read echo reply from remote", "err", err)
		return nil, err
	}

	data = frame.RawDataPayload()

	return header.ICMPv4(data), nil
}

func sendEchoReply(s *stack.Stack, nicID tcpip.NICID, src, dst tcpip.Address, localAddressBroadcast bool, payload []byte, icmpType header.ICMPv4Type, icmpCode header.ICMPv4Code) error {
	localAddr := dst
	if localAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
		localAddr = tcpip.Address{}
	}

	r, err := s.FindRoute(nicID, localAddr, src, ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		// If we cannot find a route to the destination, silently drop the packet.
		return fmt.Errorf("find route to %s failed, err: %s", src, err.String())
	}
	defer r.Release()

	if len(payload) < header.ICMPv4MinimumSize {
		return fmt.Errorf("payload too short")
	}

	// We can modify payload in place as we own it (it's a copy)
	replyICMPHdr := header.ICMPv4(payload)
	replyICMPHdr.SetType(icmpType)
	replyICMPHdr.SetCode(icmpCode) // RFC 792: EchoReply must have Code=0.
	replyICMPHdr.SetChecksum(0)
	replyICMPHdr.SetChecksum(^checksum.Checksum(payload, 0))

	replyBuf := buffer.MakeWithData(payload)
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
	defer func() {
		_ = cipher.Close()
	}()

	err := tryReuseInClient(cipher, timeout)
	if err != nil {
		log.Warn("[ICMP] underlying proxy connection is unhealthy, need close it", "err", err)
		cipher.(*cipherstream.CipherStream).MarkConnUnusable()
	} else {
		log.Debug("[ICMP] underlying proxy connection is healthy, so reuse it")
	}
}
