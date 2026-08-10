package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/relay"
	"github.com/nange/easyss/v3/server/nextproxy"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
	"github.com/nange/easyss/v3/util/bytespool"
)

type TCPHandler struct {
	dialer      *net.Dialer
	dialContext func(context.Context, string, string) (net.Conn, error)
	nextProxy   *nextproxy.NextProxy
	idleTimeout time.Duration
	dialTimeout time.Duration
}

// DialTimeout computes the dial timeout for outbound connections.
// It is derived from the base timeout: timeout/3, clamped to [3s, 15s].
func DialTimeout(timeout time.Duration) time.Duration {
	d := timeout / 3
	if d < 3*time.Second {
		d = 3 * time.Second
	}
	if d > 15*time.Second {
		d = 15 * time.Second
	}
	return d
}

func NewTCPHandler(idleTimeout, timeout time.Duration, np *nextproxy.NextProxy) *TCPHandler {
	if idleTimeout <= 0 {
		idleTimeout = 300 * time.Second
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dialTimeout := DialTimeout(timeout)
	return &TCPHandler{
		dialer:      &net.Dialer{Timeout: dialTimeout, KeepAlive: timeout},
		nextProxy:   np,
		idleTimeout: idleTimeout,
		dialTimeout: dialTimeout,
	}
}

func (h *TCPHandler) dialTarget(ctx context.Context, network, addr string) (net.Conn, error) {
	if h.nextProxy != nil && h.nextProxy.ShouldProxy(addr) {
		log.Info("[TCP_HANDLE] dialing via next proxy", "target", addr, "proxy", h.nextProxy.URL().String())
		return h.nextProxy.DialContext(ctx, network, addr)
	}
	// Test-only injection point; nil in production.
	if h.dialContext != nil {
		return h.dialContext(ctx, network, addr)
	}
	d := h.dialer
	conn, err := d.DialContext(ctx, outboundTCPNetwork(addr), addr)
	if err != nil {
		return nil, err
	}
	// Post-dial SSRF guard: verify the actual remote IP is not a LAN address.
	// This defends against DNS rebinding attacks where a domain resolves to a
	// safe public IP during the handshake validation but to a LAN IP on dial.
	if ra := conn.RemoteAddr(); ra != nil {
		if host, _, e := net.SplitHostPort(ra.String()); e == nil && util.IsLANIP(host) {
			_ = conn.Close()
			return nil, fmt.Errorf("ssrf: rejected lan destination %s", host)
		}
	}
	return conn, nil
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

// Handle relays a TCP stream between the client and the target.
// cancelRead is invoked when the relay terminates (timeout/error/completion);
// it unblocks a copy goroutine that may be stuck reading from the client
// (e.g. the HTTP/2 request body), so no goroutine lingers after the handler
// returns.
func (h *TCPHandler) Handle(ctx context.Context, dr *crypto.DecryptedReader, s2c shaper.Shaper, target string, cancelRead func()) error {
	log.Info("[TCP_HANDLE] dialing target", "target", target, "timeout", h.dialTimeout)
	targetConn, err := h.dialTarget(ctx, "tcp", target)
	if err != nil {
		log.Error("[TCP_HANDLE] dial failed", "target", target, "err", err)
		_ = s2c.PushFrame(protocol.NewFrameRST())
		_ = s2c.Flush()
		return err
	}
	defer targetConn.Close() //nolint:errcheck
	// When dialing via the next proxy, the socks5 client connection reports a
	// nil RemoteAddr (the library's RemoteAddr() returns an unset field), so
	// fall back to the configured proxy address for observability.
	remote := ""
	if h.nextProxy != nil && h.nextProxy.ShouldProxy(target) {
		remote = h.nextProxy.URL().Host
	} else if ra := targetConn.RemoteAddr(); ra != nil {
		remote = ra.String()
	}
	log.Info("[TCP_HANDLE] target connected", "target", target, "remote", remote)
	m := stats.NewStreamMeter("tcp_handle", target)
	defer m.Close()

	sendRST := func() {
		_ = s2c.PushFrame(protocol.NewFrameRST())
		_ = s2c.Flush()
	}

	result := relay.Bidirectional(h.idleTimeout, func() {
		if cancelRead != nil {
			cancelRead()
		}
		_ = targetConn.Close()
	},
		func(signal func()) error { return h.copyFromClient(dr, targetConn, signal) },
		func(signal func()) error { return h.copyFromTarget(targetConn, s2c, signal, m) },
	)
	// Log the stream outcome (bytes relayed and exit reason) at INFO level so
	// targets whose connection was established but later stalled, reset or
	// carried no data are directly visible when diagnosing blocked hosts.
	attrs := []any{"target", target, "remote", remote, "bytes", m.Bytes(), "timed_out", result.TimedOut}
	if result.Err != nil {
		attrs = append(attrs, "err", result.Err.Error())
	}
	log.Info("[TCP_HANDLE] stream closed", attrs...)
	if result.TimedOut {
		log.Debug("[TCP_HANDLE] idle timeout", "target", target, "timeout", h.idleTimeout)
		sendRST()
		return fmt.Errorf("tcp stream %s", result.IdleMsg)
	}
	if result.Err != nil {
		sendRST()
	}
	return result.Err
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

func (h *TCPHandler) copyFromTarget(src net.Conn, s2c shaper.Shaper, signalActivity func(), m *stats.StreamMeter) error {
	buf := bytespool.Get(config.ServerTCPStreamBufferSize)
	defer bytespool.MustPut(buf)
	for {
		m.SetState("read_target")
		n, err := src.Read(buf)
		if n > 0 {
			signalActivity()
			m.SetState("write_http2")
			if wErr := s2c.PushData(buf[:n]); wErr != nil {
				return wErr
			}
			m.Add(n, "read_target")
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
