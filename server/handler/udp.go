package handler

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util/bytespool"
)

const udpBufSize = 65535

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

func (h *UDPHandler) Handle(dr *crypto.DecryptedReader, s2c shaper.Shaper, target string) error {
	log.Debug("[UDP] handler starting", "target", target)

	conn, err := h.dialTarget(target)
	if err != nil {
		log.Error("[UDP] dial target failed", "target", target, "err", err)
		_ = s2c.PushFrame(protocol.NewFrameRST())
		_ = s2c.Flush()
		return err
	}
	defer conn.Close()

	done := make(chan struct{})
	closeDone := sync.OnceFunc(func() { close(done) })
	errCh := make(chan error, 1)
	go func() {
		errCh <- h.readFromTarget(conn, s2c, done)
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

	for {
		select {
		case err := <-errCh:
			closeDone()
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case res := <-frameCh:
			if res.err != nil {
				closeDone()
				return res.err
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(h.idleTimeout)
			if err := h.handleClientFrame(conn, res.frame); err != nil {
				closeDone()
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

func (h *UDPHandler) dialTarget(target string) (net.Conn, error) {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	if h.nextProxy != nil && h.nextProxy.EnableUDP() && h.nextProxy.ShouldProxy(host) {
		return h.nextProxy.Dial("udp", target)
	}
	return net.DialTimeout("udp", target, h.idleTimeout)
}

func (h *UDPHandler) readFromTarget(conn net.Conn, s2c shaper.Shaper, done <-chan struct{}) error {
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
