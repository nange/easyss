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

	rb := make([]byte, 65535)
	n, err := conn.Read(rb)
	if err != nil {
		log.Error("[ICMP] read failed", "target", target, "err", err)
		return nil, err
	}

	rm, err := icmp.ParseMessage(parseProto, rb[:n])
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
