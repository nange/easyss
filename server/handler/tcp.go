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
	"github.com/nange/easyss/v3/util/bytespool"
)

type tcpHandler struct {
	idleTimeout time.Duration
	dialTimeout time.Duration
	// dialContext is a test-only injection point for the direct dial; nil in
	// production.
	dialContext func(context.Context, string, string) (net.Conn, error)
	dial        dialer
}

// newTCPHandler creates a tcpHandler with the given idle timeout and base
// timeout. The dial timeout is derived through config.DialTimeout (base/3
// clamped to [3s, 15s]), shared with the client side.
func newTCPHandler(idleTimeout, timeout time.Duration, np *nextproxy.NextProxy) *tcpHandler {
	if idleTimeout <= 0 {
		idleTimeout = config.DefaultStreamIdleTimeout
	}
	if timeout <= 0 {
		timeout = time.Duration(config.DefaultTimeout) * time.Second
	}
	dialTimeout := config.DialTimeout(timeout)
	h := &tcpHandler{idleTimeout: idleTimeout, dialTimeout: dialTimeout}
	h.dial = dialer{
		nextProxy: np,
		useProxy:  np.ShouldProxy,
		dial: func(ctx context.Context, _ string, target string) (net.Conn, error) {
			if h.dialContext != nil {
				return h.dialContext(ctx, "tcp", target)
			}
			// KeepAlive keeps long-lived streams reaped by the kernel instead
			// of lingering half-open after a peer vanishes.
			d := &net.Dialer{Timeout: dialTimeout, KeepAlive: timeout}
			return d.DialContext(ctx, outboundTCPNetwork(target), target)
		},
	}
	return h
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
func (h *tcpHandler) Handle(ctx context.Context, dr *crypto.DecryptedReader, s2c shaper.Shaper, target string, cancelRead func()) error {
	log.Info("[TCP_HANDLE] dialing target", "target", target)
	targetConn, remote, err := h.dial.dialTarget(ctx, "tcp", target)
	if err != nil {
		log.Error("[TCP_HANDLE] dial failed", "target", target, "err", err)
		sendRST(s2c)
		return err
	}
	defer targetConn.Close() //nolint:errcheck
	log.Info("[TCP_HANDLE] target connected", "target", target, "remote", remote)
	m := stats.NewStreamMeter("tcp_handle", target)
	defer m.Close()

	// The relay's onClose must both unblock the client reader (cancelRead) and
	// close the target connection, so the generic CloseBoth is composed with
	// that callback here.
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
		sendRST(s2c)
		return fmt.Errorf("tcp stream idle timeout after %v", h.idleTimeout)
	}
	if result.Err != nil {
		sendRST(s2c)
	}
	return result.Err
}

func (h *tcpHandler) copyFromClient(dr *crypto.DecryptedReader, dst net.Conn, signalActivity func()) error {
	for {
		frame, done, err := nextClientFrame(dr)
		if err != nil {
			return err
		}
		if done {
			if frame.Type == protocol.FrameRST {
				return io.EOF
			}
			signalActivity()
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
			// FIN is a terminal frame: the client sends no further frames
			// after it (its copyLocalToRemote returns right after flushing
			// FIN), so stop reading instead of blocking on ReadFrame until
			// the relay idle timeout. The relay keeps waiting for the
			// target->client direction and its idle timer still bounds the
			// stream's lifetime.
			return nil
		}
		signalActivity()
		if len(frame.Payload) > 0 {
			if _, wErr := dst.Write(frame.Payload); wErr != nil {
				return wErr
			}
		}
	}
}

func (h *tcpHandler) copyFromTarget(src net.Conn, s2c shaper.Shaper, signalActivity func(), m *stats.StreamMeter) error {
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
