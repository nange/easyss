package handler

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util/bytespool"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type ICMPHandler struct {
}

func NewICMPHandler() *ICMPHandler {
	return &ICMPHandler{}
}

func (h *ICMPHandler) Handle(dr *crypto.DecryptedReader, s2c shaper.Shaper, target string) error {
	for {
		frame, err := dr.ReadFrame()
		if err != nil {
			return err
		}

		switch frame.Type {
		case protocol.FrameDATA:
			replyPayload, err := h.icmpExchange(target, frame.Payload)
			if err != nil {
				_ = s2c.PushFrame(protocol.NewFrameRST())
				_ = s2c.Flush()
				return err
			}

			dataFrame := protocol.NewFrameDATA(replyPayload)
			finFrame := protocol.NewFrameFIN()
			_ = s2c.PushFrame(dataFrame)
			_ = s2c.PushFrame(finFrame)
			_ = s2c.Flush()
			return nil

		case protocol.FrameFIN, protocol.FrameRST:
			return nil
		case protocol.FramePADDING, protocol.FrameCOVER:
			continue
		}
	}
}

func (h *ICMPHandler) icmpExchange(target string, payload []byte) ([]byte, error) {
	log.Debug("[ICMP] exchange", "target", target)

	if len(payload) < 4 {
		return nil, io.ErrUnexpectedEOF
	}

	isIPv6 := isIPv6Target(target)
	dialNet := "ip4:icmp"
	parseProto := 1
	if isIPv6 {
		dialNet = "ip6:ipv6-icmp"
		parseProto = 58
	}

	conn, err := net.DialTimeout(dialNet, target, 5*time.Second)
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

	msg := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(binary.BigEndian.Uint16(payload[:2])),
			Seq:  int(binary.BigEndian.Uint16(payload[2:4])),
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
	n, err := conn.Read(rb)
	if err != nil {
		log.Error("[ICMP] read failed", "target", target, "err", err)
		return nil, err
	}

	data := rb[:n]
	// On Linux (and Windows) raw "ip4:icmp" sockets return the IPv4 header
	// prepended to the ICMP payload, while macOS/BSD raw sockets already strip
	// it. If the first nibble looks like an IPv4 header (version 4), peel it off
	// before handing the payload to icmp.ParseMessage, otherwise the IP header
	// is misparsed as the ICMP type (e.g. 0x45 -> type 69) and echo replies are
	// never recognised, silently breaking ICMP on the primary server platform.
	if !isIPv6 && len(data) > 0 && data[0]>>4 == 4 {
		ihl := int(data[0]&0x0F) * 4
		if ihl >= 20 && ihl < len(data) {
			data = data[ihl:]
		}
	}

	rm, err := icmp.ParseMessage(parseProto, data)
	if err != nil {
		return nil, err
	}

	var replyType icmp.Type
	if isIPv6 {
		replyType = ipv6.ICMPTypeEchoReply
	} else {
		replyType = ipv4.ICMPTypeEchoReply
	}
	if rm.Type != replyType {
		return payload, nil
	}

	switch body := rm.Body.(type) {
	case *icmp.Echo:
		result := make([]byte, 4+len(body.Data))
		binary.BigEndian.PutUint16(result[:2], uint16(body.ID))
		binary.BigEndian.PutUint16(result[2:4], uint16(body.Seq))
		copy(result[4:], body.Data)
		return result, nil
	default:
		return payload, nil
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
