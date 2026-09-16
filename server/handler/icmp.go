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

// newICMPHandler creates an icmpHandler. The outbound ICMP dial timeout is
// derived through config.DialTimeout (base/3 clamped to [3s, 15s]), shared
// with the TCP/UDP handlers' dials.
func newICMPHandler(timeout time.Duration) *icmpHandler {
	if timeout <= 0 {
		timeout = time.Duration(config.DefaultTimeout) * time.Second
	}
	dialTimeout := config.DialTimeout(timeout)
	return &icmpHandler{
		dial: dialer{
			dial: func(_ context.Context, network, target string) (net.Conn, error) {
				return net.DialTimeout(network, target, dialTimeout)
			},
		},
	}
}

// Handle relays one ICMP echo exchange per stream: it reads the client's
// echo request (DATA frame, skipping PADDING/COVER), performs the exchange
// and answers with the reply plus FIN. Unlike the TCP/UDP handlers it
// carries no context and no cancelRead: the exchange is self-contained and
// bounded by its own read deadline, and the stream ends after the reply.
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
	dialNet := "ip4:icmp"
	parseProto := 1
	if isIPv6 {
		dialNet = "ip6:ipv6-icmp"
		parseProto = 58
	}

	// The shared dialer expects a context; ICMP has none (see Handle), so a
	// background context is used. The dial timeout still bounds the dial
	// itself, and the post-dial SSRF guard runs inside dialTarget.
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

	// Raw ICMP sockets receive every matching ICMP packet delivered to the
	// host, not just replies to this socket's own request: a concurrent
	// stream to the same target can produce replies whose ID/Seq belong to
	// the other stream. Keep reading until the deadline, ignoring packets
	// whose ID/Seq do not match what we sent. ICMP error packets (destination
	// unreachable, time exceeded) never match, so they surface as a timeout
	// error instead of being misreported as a successful reply.
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
