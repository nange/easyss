package handler

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/util/bytespool"
)

const udpBufSize = protocol.MaxPlainRecordSize - protocol.FrameHeaderSize

type UDPHandler struct {
	idleTimeout time.Duration
	nextProxy   *nextproxy.NextProxy
}

func NewUDPHandler(idleTimeout time.Duration, np *nextproxy.NextProxy) *UDPHandler {
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}
	h := &UDPHandler{
		idleTimeout: idleTimeout,
		nextProxy:   np,
	}
	return h
}

func (h *UDPHandler) Handle(ctx context.Context, dr *crypto.DecryptedReader, s2c shaper.Shaper, target string) error {
	log.Debug("[UDP] handler starting", "target", target)

	conn, err := h.dialTarget(ctx, target)
	if err != nil {
		log.Error("[UDP] dial target failed", "target", target, "err", err)
		_ = s2c.PushFrame(protocol.NewFrameRST())
		_ = s2c.Flush()
		return err
	}
	defer conn.Close() //nolint:errcheck

	var dnsDetected atomic.Bool
	var dnsChecked  atomic.Bool

	done := make(chan struct{})
	closeDone := sync.OnceFunc(func() { close(done) })
	errCh := make(chan error, 1)
	go func() {
		errCh <- h.readFromTarget(conn, s2c, done, &dnsDetected)
	}()
	frameCh := make(chan udpFrameResult, 1)
	go func() {
		for {
			frame, err := dr.ReadFrame()
			frameCh <- udpFrameResult{frame: frame, err: err}
			if err != nil {
				return
			}
		}
	}()
	timer := time.NewTimer(h.idleTimeout)
	defer timer.Stop()

	sendRST := func() {
		_ = s2c.PushFrame(protocol.NewFrameRST())
		_ = s2c.Flush()
	}

	for {
		select {
		case err := <-errCh:
			closeDone()
			if errors.Is(err, io.EOF) {
				return nil
			}
			sendRST()
			return err
		case res := <-frameCh:
			if res.err != nil {
				closeDone()
				sendRST()
				return res.err
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(h.idleTimeout)

			// DNS query detection (only on first DATAGRAM frame)
			if !dnsChecked.Load() && h.nextProxy != nil &&
				res.frame.Type == protocol.FrameDATAGRAM && len(res.frame.Payload) > 0 {
				msg := &dns.Msg{}
				if err := msg.Unpack(res.frame.Payload); err == nil && util.IsDNSRequest(msg) {
					dnsDetected.Store(true)
					domain := strings.TrimSuffix(msg.Question[0].Name, ".")
					viaProxy := h.nextProxy.IsCustomDomain(domain)
					log.Info("[UDP_DNS]", "domain", domain, "target", target, "via_proxy", viaProxy)
				}
				dnsChecked.Store(true)
			}

			if err := h.handleClientFrame(conn, res.frame); err != nil {
				closeDone()
				sendRST()
				return err
			}
			if res.frame.Type == protocol.FrameFIN || res.frame.Type == protocol.FrameRST {
				closeDone()
				return nil
			}
		case <-timer.C:
			closeDone()
			log.Debug("[UDP] idle timeout", "target", target, "timeout", h.idleTimeout)
			return nil
		}
	}
}

type udpFrameResult struct {
	frame protocol.Frame
	err   error
}

func (h *UDPHandler) handleClientFrame(conn net.Conn, frame protocol.Frame) error {
	switch frame.Type {
	case protocol.FrameDATAGRAM:
		if len(frame.Payload) > 0 {
			_, err := conn.Write(frame.Payload)
			return err
		}
	case protocol.FrameFIN, protocol.FrameRST, protocol.FramePADDING, protocol.FrameCOVER:
		return nil
	}
	return nil
}

func (h *UDPHandler) dialTarget(ctx context.Context, target string) (net.Conn, error) {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	if h.nextProxy != nil && h.nextProxy.EnableUDP() && h.nextProxy.ShouldProxy(host) {
		log.Info("[UDP] dialing via next proxy", "target", target, "proxy", h.nextProxy.URL().String())
		return h.nextProxy.DialContext(ctx, "udp", target)
	}
	return net.DialTimeout("udp", target, h.idleTimeout)
}

func (h *UDPHandler) readFromTarget(conn net.Conn, s2c shaper.Shaper, done <-chan struct{}, dnsDetected *atomic.Bool) error {
	buf := bytespool.Get(udpBufSize)
	defer bytespool.MustPut(buf)
	for {
		select {
		case <-done:
			return io.EOF
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(h.idleTimeout))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return io.EOF
			}
			if strings.Contains(err.Error(), "use of closed network connection") {
				return io.EOF
			}
			log.Error("[UDP] read from target failed", "target", conn.RemoteAddr().String(), "err", err)
			return err
		}
		if n > 0 {
			// DNS response interception for dynamic IP learning
			if dnsDetected.Load() && h.nextProxy != nil {
				msg := &dns.Msg{}
				if err := msg.Unpack(buf[:n]); err == nil && msg.Response && len(msg.Question) > 0 {
					domain := strings.TrimSuffix(msg.Question[0].Name, ".")
					if h.nextProxy.IsCustomDomain(domain) {
						for _, ans := range msg.Answer {
							switch a := ans.(type) {
							case *dns.A:
								h.nextProxy.AddIP(a.A.String())
							case *dns.AAAA:
								h.nextProxy.AddIP(a.AAAA.String())
							}
						}
					}
				}
			}

			frame := protocol.NewFrameDATAGRAM(buf[:n])
			if wErr := s2c.PushFrame(frame); wErr != nil {
				return wErr
			}
			if fErr := s2c.Flush(); fErr != nil {
				return fErr
			}
		}
	}
}
