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
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/util/bytespool"
)

const udpBufSize = protocol.MaxUDPDataSize

type udpHandler struct {
	idleTimeout time.Duration
	dialTimeout time.Duration
	dial        dialer
}

// newUDPHandler creates a udpHandler with the given idle timeout and base
// timeout. Like newTCPHandler, the dial timeout is derived through
// config.DialTimeout (base/3 clamped to [3s, 15s]) instead of reusing the
// much longer idle timeout.
func newUDPHandler(idleTimeout, timeout time.Duration, np *nextproxy.NextProxy) *udpHandler {
	if idleTimeout <= 0 {
		idleTimeout = config.DefaultUDPIdleTimeout
	}
	if timeout <= 0 {
		timeout = time.Duration(config.DefaultTimeout) * time.Second
	}
	dialTimeout := config.DialTimeout(timeout)
	return &udpHandler{
		idleTimeout: idleTimeout,
		dialTimeout: dialTimeout,
		dial: dialer{
			nextProxy: np,
			useProxy: func(target string) bool {
				return np.EnableUDP() && np.ShouldProxy(target)
			},
			dial: func(ctx context.Context, network, target string) (net.Conn, error) {
				return net.DialTimeout(network, target, dialTimeout)
			},
		},
	}
}

// Handle relays UDP datagrams between the client stream and the target.
// cancelRead is invoked when the handler terminates (idle timeout/error/
// FIN): it unblocks the frame-reader goroutine that may be stuck reading the
// client's request body, so no goroutine lingers after ServeHTTP returns.
func (h *udpHandler) Handle(ctx context.Context, dr *crypto.DecryptedReader, s2c shaper.Shaper, target string, cancelRead func()) error {
	log.Debug("[UDP] handler starting", "target", target)

	conn, remote, err := h.dial.dialTarget(ctx, "udp", target)
	if err != nil {
		log.Error("[UDP] dial target failed", "target", target, "err", err)
		sendRST(s2c)
		return err
	}
	var dnsDetected atomic.Bool
	var dnsChecked atomic.Bool

	done := make(chan struct{})
	closeDone := sync.OnceFunc(func() {
		close(done)
		if cancelRead != nil {
			cancelRead()
		}
	})
	defer closeDone()
	defer conn.Close() //nolint:errcheck
	errCh := make(chan error, 1)
	go func() {
		errCh <- h.readFromTarget(conn, s2c, done, &dnsDetected, remote)
	}()
	frameCh := make(chan udpFrameResult, 1)
	go func() {
		for {
			frame, err := dr.ReadFrame()
			select {
			case frameCh <- udpFrameResult{frame: frame, err: err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	timer := time.NewTimer(h.idleTimeout)
	defer timer.Stop()

	for {
		select {
		case err := <-errCh:
			closeDone()
			if errors.Is(err, io.EOF) {
				return nil
			}
			sendRST(s2c)
			return err
		case res := <-frameCh:
			if res.err != nil {
				closeDone()
				sendRST(s2c)
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
			if !dnsChecked.Load() && h.dial.nextProxy != nil &&
				res.frame.Type == protocol.FrameDATAGRAM && len(res.frame.Payload) > 0 {
				msg := &dns.Msg{}
				if err := msg.Unpack(res.frame.Payload); err == nil && util.IsDNSRequest(msg) {
					dnsDetected.Store(true)
					domain := strings.TrimSuffix(msg.Question[0].Name, ".")
					viaNextProxy := h.dial.nextProxy.IsCustomDomain(domain)
					log.Info("[UDP_DNS]", "domain", domain, "target", target, "via_next_proxy", viaNextProxy)
				}
				dnsChecked.Store(true)
			}

			if err := h.handleClientFrame(conn, res.frame); err != nil {
				closeDone()
				sendRST(s2c)
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

func (h *udpHandler) handleClientFrame(conn net.Conn, frame protocol.Frame) error {
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

func (h *udpHandler) readFromTarget(conn net.Conn, s2c shaper.Shaper, done <-chan struct{}, dnsDetected *atomic.Bool, remote string) error {
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return io.EOF
			}
			if errors.Is(err, net.ErrClosed) {
				return io.EOF
			}
			log.Error("[UDP] read from target failed", "target", remote, "err", err)
			return err
		}
		if n > 0 {
			// DNS response interception for dynamic IP learning
			if dnsDetected.Load() && h.dial.nextProxy != nil {
				msg := &dns.Msg{}
				if err := msg.Unpack(buf[:n]); err == nil && util.IsDNSResponse(msg) {
					domain := strings.TrimSuffix(msg.Question[0].Name, ".")
					if h.dial.nextProxy.IsCustomDomain(domain) {
						util.ForEachDNSAnswer(msg, func(kind, value string) {
							if kind == "CNAME" {
								h.dial.nextProxy.AddDomain(value)
								return
							}
							h.dial.nextProxy.AddIP(value)
						})
					}
				}
			}

			frame := protocol.NewFrameDATAGRAM(buf[:n])
			if wErr := s2c.PushFrame(frame); wErr != nil {
				return wErr
			}
		}
	}
}
