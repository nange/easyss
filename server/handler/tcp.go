package handler

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/util/bytespool"
)

type TCPHandler struct {
	dialer      *net.Dialer
	nextProxy   *nextproxy.NextProxy
	idleTimeout time.Duration
	dialTimeout time.Duration
}

type tcpStreamMeter struct {
	target       string
	total        atomic.Int64
	last         atomic.Int64
	state        atomic.Value
	lastLoggedAt atomic.Int64
	done         chan struct{}
}

func newTCPStreamMeter(target string) *tcpStreamMeter {
	m := &tcpStreamMeter{
		target: target,
		done:   make(chan struct{}),
	}
	m.state.Store("open")
	go m.loop()
	return m
}

func (m *tcpStreamMeter) add(n int, state string) {
	if n > 0 {
		m.total.Add(int64(n))
	}
	m.setState(state)
}

func (m *tcpStreamMeter) setState(state string) {
	if state != "" {
		m.state.Store(state)
	}
}

func (m *tcpStreamMeter) close() {
	close(m.done)
}

func (m *tcpStreamMeter) loop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			total := m.total.Load()
			last := m.last.Swap(total)
			if total >= 1<<20 && total == last {
				now := time.Now().Unix()
				if prev := m.lastLoggedAt.Load(); now-prev >= 60 {
					m.lastLoggedAt.Store(now)
					log.Info("[TCP_HANDLE] downstream stalled", "target", m.target, "bytes", total, "state", m.state.Load())
				}
			}
		case <-m.done:
			return
		}
	}
}

func NewTCPHandler(idleTimeout time.Duration, np *nextproxy.NextProxy) *TCPHandler {
	if idleTimeout <= 0 {
		idleTimeout = 120 * time.Second
	}
	dialTimeout := idleTimeout * 2
	if dialTimeout < 30*time.Second {
		dialTimeout = 30 * time.Second
	}
	return &TCPHandler{
		dialer:      &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second},
		nextProxy:   np,
		idleTimeout: idleTimeout,
		dialTimeout: dialTimeout,
	}
}

func (h *TCPHandler) dialTarget(network, addr string) (net.Conn, error) {
	if h.nextProxy != nil && h.nextProxy.ShouldProxy(addr) {
		return h.nextProxy.Dial(network, addr)
	}
	return h.dialer.Dial(outboundTCPNetwork(addr), addr)
}

func outboundTCPNetwork(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "tcp"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "tcp"
	}
	if ip.To4() == nil {
		return "tcp6"
	}
	return "tcp4"
}

func (h *TCPHandler) Handle(dr *crypto.DecryptedReader, s2c shaper.Shaper, target string) error {
	log.Info("[TCP_HANDLE] dialing target", "target", target, "timeout", h.dialTimeout)
	targetConn, err := h.dialTarget("tcp", target)
	if err != nil {
		log.Error("[TCP_HANDLE] dial failed", "target", target, "err", err)
		_ = s2c.PushFrame(protocol.NewFrameRST())
		_ = s2c.Flush()
		return err
	}
	defer targetConn.Close() //nolint:errcheck
	log.Info("[TCP_HANDLE] target connected", "target", target, "remote", targetConn.RemoteAddr().String())
	meter := newTCPStreamMeter(target)
	defer meter.close()

	errCh := make(chan error, 2)
	activity := make(chan struct{}, 1)
	signalActivity := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}

	go func() {
		errCh <- h.copyFromClient(dr, targetConn, signalActivity)
	}()

	go func() {
		errCh <- h.copyFromTarget(targetConn, s2c, signalActivity, meter)
	}()

	timer := time.NewTimer(h.idleTimeout)
	defer timer.Stop()

	done := 0
	var firstErr error
	for done < 2 {
		select {
		case err = <-errCh:
			done++
			if err != nil && !errors.Is(err, io.EOF) && firstErr == nil {
				firstErr = err
			}
			if firstErr != nil || done == 2 {
				return firstErr
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(h.idleTimeout)
		case <-activity:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(h.idleTimeout)
		case <-timer.C:
			_ = targetConn.Close()
			log.Debug("[TCP_HANDLE] idle timeout", "target", target, "timeout", h.idleTimeout)
			return fmt.Errorf("tcp stream idle timeout after %v", h.idleTimeout)
		}
	}
	return firstErr
}

func (h *TCPHandler) copyFromClient(dr *crypto.DecryptedReader, dst net.Conn, signalActivity func()) error {
	for {
		frame, err := dr.ReadFrame()
		if err != nil {
			return err
		}

		switch frame.Type {
		case protocol.FrameDATA:
			signalActivity()
			if len(frame.Payload) > 0 {
				if _, wErr := dst.Write(frame.Payload); wErr != nil {
					return wErr
				}
			}
		case protocol.FrameFIN:
			signalActivity()
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
			continue
		case protocol.FrameRST:
			return io.EOF
		case protocol.FramePADDING, protocol.FrameCOVER:
			continue
		}
	}
}

func (h *TCPHandler) copyFromTarget(src net.Conn, s2c shaper.Shaper, signalActivity func(), meter *tcpStreamMeter) error {
	buf := bytespool.Get(config.TCPStreamBufferSize)
	defer bytespool.MustPut(buf)
	for {
		meter.setState("read_target")
		n, err := src.Read(buf)
		if n > 0 {
			signalActivity()
			frame := protocol.NewFrameDATA(buf[:n])
			meter.setState("write_http2")
			if wErr := s2c.PushFrame(frame); wErr != nil {
				return wErr
			}
			meter.add(n, "read_target")
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				finFrame := protocol.NewFrameFIN()
				_ = s2c.PushFrame(finFrame)
				_ = s2c.Flush()
				signalActivity()
				return nil
			}
			return err
		}
	}
}
