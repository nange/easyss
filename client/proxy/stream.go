package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/transport"
	"github.com/nange/easyss/v3/util/bytespool"
)

var ErrStreamIdleTimeout = errors.New("stream idle timeout")

var errLocalConnClosed = errors.New("local connection closed")

type streamMeter struct {
	component    string
	target       string
	total        atomic.Int64
	last         atomic.Int64
	state        atomic.Value
	lastLoggedAt atomic.Int64
	done         chan struct{}
}

func newStreamMeter(component, target string) *streamMeter {
	m := &streamMeter{
		component: component,
		target:    target,
		done:      make(chan struct{}),
	}
	m.state.Store("open")
	go m.loop()
	return m
}

func (m *streamMeter) add(n int, state string) {
	if n > 0 {
		m.total.Add(int64(n))
	}
	m.setState(state)
}

func (m *streamMeter) setState(state string) {
	if state != "" {
		m.state.Store(state)
	}
}

func (m *streamMeter) close() {
	close(m.done)
}

func (m *streamMeter) loop() {
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
					log.Info("[STREAM] downstream stalled", "component", m.component, "target", m.target, "bytes", total, "state", m.state.Load())
				}
			}
		case <-m.done:
			return
		}
	}
}

type StreamHandler struct {
	transport         transport.Transport
	masterKey         []byte
	shaperCfg         shaper.Config
	streamIdleTimeout time.Duration
	OnRTT             func(time.Duration)
}

func NewStreamHandler(tr transport.Transport, masterKey []byte, shaperCfg shaper.Config, streamIdleTimeout time.Duration) *StreamHandler {
	if streamIdleTimeout <= 0 {
		streamIdleTimeout = 120 * time.Second
	}
	return &StreamHandler{
		transport:         tr,
		masterKey:         masterKey,
		shaperCfg:         shaperCfg,
		streamIdleTimeout: streamIdleTimeout,
	}
}

func (h *StreamHandler) OpenTCPStream(ctx context.Context, target string, method protocol.Method, localConn net.Conn) error {
	stats.RecordTCPConnection()
	return h.openStream(ctx, "/v3/tcp", protocol.ProtoTCP, target, method, localConn)
}

func (h *StreamHandler) OpenUDPStream(ctx context.Context, target string, method protocol.Method, localConn net.Conn) error {
	return h.openStream(ctx, "/v3/udp", protocol.ProtoUDP, target, method, localConn)
}

func (h *StreamHandler) OpenICMPStream(ctx context.Context, target string, echoPayload []byte, method protocol.Method) ([]byte, error) {
	return h.icmpStream(ctx, "/v3/icmp", protocol.ProtoICMP, target, echoPayload, method)
}

func (h *StreamHandler) icmpStream(ctx context.Context, endpoint string, proto protocol.Proto, target string, echoPayload []byte, method protocol.Method) ([]byte, error) {
	log.Debug("[STREAM] icmp open", "endpoint", endpoint, "target", target)

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	saltB64 := base64.RawURLEncoding.EncodeToString(salt)

	req := transport.OpenRequest{
		Endpoint: endpoint,
		Salt:     saltB64,
	}
	stream, err := h.transport.Open(ctx, req)
	if err != nil {
		log.Error("[STREAM] icmp transport open", "target", target, "err", err)
		return nil, fmt.Errorf("transport open: %w", err)
	}
	defer stream.Close() //nolint:errcheck

	sk, err := crypto.NewStreamKeys(h.masterKey, salt, endpoint)
	if err != nil {
		return nil, fmt.Errorf("stream keys: %w", err)
	}

	bootstrapEnc, bootstrapCounter, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	if err != nil {
		return nil, fmt.Errorf("bootstrap encryptor: %w", err)
	}
	aad := crypto.BuildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)
	rw := crypto.NewRecordWriter(stream, bootstrapEnc, bootstrapCounter, aad)

	handshake := protocol.Handshake{
		Version: protocol.Version3,
		Proto:   proto,
		Method:  method,
		Target:  target,
	}
	hsFrame := protocol.NewFrameHANDSHAKE(handshake)
	dataFrame := protocol.NewFrameDATA(echoPayload)

	plaintext := protocol.EncodeFrames([]protocol.Frame{hsFrame, dataFrame})
	if err := rw.WriteRecord(plaintext); err != nil {
		log.Error("[STREAM] icmp handshake write", "target", target, "err", err)
		return nil, fmt.Errorf("write handshake+data: %w", err)
	}

	aadS2C := crypto.BuildAAD(endpoint, salt, "s2c", "session", method)
	s2cEnc, s2cCounter, err := sk.Encryptor("s2c", "session", method)
	if err != nil {
		return nil, fmt.Errorf("s2c encryptor: %w", err)
	}
	dr := crypto.NewDecryptedReader(stream, aadS2C, s2cEnc, s2cCounter)

	frame, err := dr.ReadFrame()
	if err != nil {
		log.Error("[STREAM] icmp read reply", "target", target, "err", err)
		return nil, fmt.Errorf("read first reply frame: %w", err)
	}

	if frame.Type == protocol.FrameRST {
		log.Error("[STREAM] icmp rejected", "target", target)
		return nil, fmt.Errorf("icmp rejected by server")
	}

	if frame.Type != protocol.FrameDATA {
		return nil, fmt.Errorf("expected DATA frame, got %d", frame.Type)
	}

	return frame.Payload, nil
}

func (h *StreamHandler) openStream(ctx context.Context, endpoint string, proto protocol.Proto, target string, method protocol.Method, localConn net.Conn) error {
	log.Debug("[STREAM] opening", "endpoint", endpoint, "target", target)

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	saltB64 := base64.RawURLEncoding.EncodeToString(salt)

	req := transport.OpenRequest{
		Endpoint: endpoint,
		Salt:     saltB64,
	}
	stream, err := h.transport.Open(ctx, req)
	if err != nil {
		log.Error("[STREAM] transport open", "endpoint", endpoint, "target", target, "err", err)
		return fmt.Errorf("transport open: %w", err)
	}
	log.Debug("[STREAM] transport opened", "endpoint", endpoint, "target", target)

	sk, err := crypto.NewStreamKeys(h.masterKey, salt, endpoint)
	if err != nil {
		stream.Close() //nolint:errcheck
		return fmt.Errorf("stream keys: %w", err)
	}

	bootstrapEnc, bootstrapCounter, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	if err != nil {
		stream.Close() //nolint:errcheck
		return fmt.Errorf("bootstrap encryptor: %w", err)
	}
	aad := crypto.BuildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)
	rw := crypto.NewRecordWriter(stream, bootstrapEnc, bootstrapCounter, aad)

	handshake := protocol.Handshake{
		Version: protocol.Version3,
		Proto:   proto,
		Method:  method,
		Target:  target,
	}
	hsFrame := protocol.NewFrameHANDSHAKE(handshake)

	frames := []protocol.Frame{hsFrame}
	if localConn != nil {
		_ = localConn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
			buf := bytespool.Get(config.TCPStreamBufferSize)
			n, rErr := localConn.Read(buf)
		_ = localConn.SetReadDeadline(time.Time{})
		if n > 0 {
			frames = append(frames, protocol.NewFrameDATA(buf[:n]))
			log.Debug("[STREAM] merged first DATA into bootstrap record", "bytes", n, "read_err", rErr)
		}
		bytespool.MustPut(buf)
	}

	plaintext := protocol.EncodeFrames(frames)
	if err := rw.WriteRecord(plaintext); err != nil {
		stream.Close() //nolint:errcheck
		log.Error("[STREAM] handshake write", "endpoint", endpoint, "target", target, "err", err)
		return fmt.Errorf("write handshake: %w", err)
	}
	log.Debug("[STREAM] handshake sent", "target", target)

	aadSession := crypto.BuildAAD(endpoint, salt, "c2s", "session", method)
	sessionEnc, sessionCounter, err := sk.Encryptor("c2s", "session", method)
	if err != nil {
		stream.Close() //nolint:errcheck
		return fmt.Errorf("session encryptor: %w", err)
	}
	sessionWriter := crypto.NewRecordWriter(stream, sessionEnc, sessionCounter, aadSession)

	txShaper := shaper.NewLight(sessionWriter, h.shaperCfg)
	defer txShaper.Close() //nolint:errcheck

	aadS2C := crypto.BuildAAD(endpoint, salt, "s2c", "session", method)
	s2cEnc, s2cCounter, err := sk.Encryptor("s2c", "session", method)
	if err != nil {
		stream.Close() //nolint:errcheck
		return fmt.Errorf("s2c encryptor: %w", err)
	}
	dr := crypto.NewDecryptedReader(stream, aadS2C, s2cEnc, s2cCounter)

	err = h.relay(target, localConn, txShaper, dr, stream)
	log.Debug("[STREAM] relay finished", "endpoint", endpoint, "target", target, "err", err)
	return err
}

func (h *StreamHandler) relay(target string, localConn net.Conn, tx shaper.Shaper, rx *crypto.DecryptedReader, stream transport.Stream) error {
	meter := newStreamMeter("client", target)
	defer meter.close()

	activity := make(chan struct{}, 1)
	signalActivity := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}
	errCh := make(chan error, 2)

	go func() {
		errCh <- h.copyLocalToRemote(localConn, tx, signalActivity)
	}()

	go func() {
		errCh <- h.copyRemoteToLocal(rx, localConn, signalActivity, meter)
	}()

	timer := time.NewTimer(h.streamIdleTimeout)
	defer timer.Stop()

	done := 0
	var firstErr error
	for done < 2 {
		select {
		case err := <-errCh:
			done++
			if errors.Is(err, errLocalConnClosed) || errors.Is(err, io.ErrClosedPipe) {
				_ = stream.Close()
				_ = localConn.Close()
				return nil
			}
			if err != nil && !errors.Is(err, io.EOF) && firstErr == nil {
				firstErr = err
				log.Debug("[STREAM] relay copy error", "err", err)
			}
			if firstErr != nil || done == 2 {
				_ = stream.Close()
				_ = localConn.Close()
				return firstErr
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(h.streamIdleTimeout)
		case <-activity:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(h.streamIdleTimeout)
		case <-timer.C:
			log.Debug("[STREAM] idle timeout", "timeout", h.streamIdleTimeout)
			_ = stream.Close()
			_ = localConn.Close()
			return fmt.Errorf("%w after %v", ErrStreamIdleTimeout, h.streamIdleTimeout)
		}
	}

	return firstErr
}

func (h *StreamHandler) copyLocalToRemote(src net.Conn, tx shaper.Shaper, signalActivity func()) error {
	buf := bytespool.Get(config.TCPStreamBufferSize)
	defer bytespool.MustPut(buf)
	for {
		n, err := src.Read(buf)
			if n > 0 {
		signalActivity()
				stats.RecordProxyBytesSent(n)
				frame := protocol.NewFrameDATA(buf[:n])
			if pErr := tx.PushFrame(frame); pErr != nil {
				_ = tx.Flush()
				if errors.Is(pErr, io.ErrClosedPipe) {
					return nil
				}
				return pErr
			}
		}
		if err != nil {
			finFrame := protocol.NewFrameFIN()
			_ = tx.PushFrame(finFrame)
			_ = tx.Flush()
			signalActivity()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if isLocalConnClosedError(err) {
				log.Debug("[STREAM] local connection closed", "err", err)
				return errLocalConnClosed
			}
			log.Debug("[STREAM] local read error", "err", err)
			return err
		}
	}
}

func (h *StreamHandler) copyRemoteToLocal(rx *crypto.DecryptedReader, dst net.Conn, signalActivity func(), meter *streamMeter) error {
	type frameItem struct {
		data []byte
		fin  bool
		rst  bool
	}

	ch := make(chan frameItem, 16)
	readDone := make(chan error, 1)
	done := make(chan struct{})
	defer close(done)

	go func() {
		defer close(ch)
		start := time.Now()
		first := true
		for {
			frame, err := rx.ReadFrame()
			if first {
				first = false
				if h.OnRTT != nil {
					h.OnRTT(time.Since(start))
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					readDone <- nil
				} else {
					log.Debug("[STREAM] remote read error", "err", err)
					readDone <- err
				}
				return
			}

			switch frame.Type {
			case protocol.FrameDATA:
				signalActivity()
				if len(frame.Payload) > 0 {
					select {
					case ch <- frameItem{data: frame.Payload}:
					case <-done:
						readDone <- nil
						return
					}
				}
			case protocol.FrameFIN:
				signalActivity()
				select {
				case ch <- frameItem{fin: true}:
				case <-done:
				}
				readDone <- nil
				return
			case protocol.FrameRST:
				select {
				case ch <- frameItem{rst: true}:
				case <-done:
				}
				readDone <- nil
				return
			case protocol.FramePADDING, protocol.FrameCOVER:
				continue
			}
		}
	}()

	for item := range ch {
		if item.rst {
			return fmt.Errorf("stream reset by peer")
		}
		if item.fin {
			return nil
		}
		meter.setState("write_local")
			if _, wErr := dst.Write(item.data); wErr != nil {
				if isLocalConnClosedError(wErr) {
					log.Debug("[STREAM] local connection closed", "err", wErr)
					return errLocalConnClosed
				}
				return wErr
			}
		stats.RecordProxyBytesRecv(len(item.data))
			meter.add(len(item.data), "read_remote")
	}

	return <-readDone
}

func isLocalConnClosedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "forcibly closed by the remote host") ||
		strings.Contains(msg, "software caused connection abort") ||
		strings.Contains(msg, "connection was aborted") ||
		strings.Contains(msg, "broken pipe")
}

type UDPExchange struct {
	stream   transport.Stream
	tx       shaper.Shaper
	reader   *crypto.DecryptedReader
	target   string
	lastSeen time.Time
	mu       sync.Mutex
}

func (h *StreamHandler) OpenUDPExchange(ctx context.Context, target string, method protocol.Method) (*UDPExchange, error) {
	stats.RecordUDPAssociation()
	log.Debug("[UDP_EXCHANGE] opening", "target", target)

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	saltB64 := base64.RawURLEncoding.EncodeToString(salt)

	req := transport.OpenRequest{
		Endpoint: "/v3/udp",
		Salt:     saltB64,
	}
	stream, err := h.transport.Open(ctx, req)
	if err != nil {
		log.Error("[UDP_EXCHANGE] transport open", "target", target, "err", err)
		return nil, fmt.Errorf("transport open: %w", err)
	}

	sk, err := crypto.NewStreamKeys(h.masterKey, salt, "/v3/udp")
	if err != nil {
		stream.Close() //nolint:errcheck
		return nil, fmt.Errorf("stream keys: %w", err)
	}

	bootstrapEnc, bootstrapCounter, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	if err != nil {
		stream.Close() //nolint:errcheck
		return nil, fmt.Errorf("bootstrap encryptor: %w", err)
	}
	aadBootstrap := crypto.BuildAAD("/v3/udp", salt, "c2s", "bootstrap", protocol.MethodAES256GCM)
	rw := crypto.NewRecordWriter(stream, bootstrapEnc, bootstrapCounter, aadBootstrap)

	handshake := protocol.Handshake{
		Version: protocol.Version3,
		Proto:   protocol.ProtoUDP,
		Method:  method,
		Target:  target,
	}
	hsFrame := protocol.NewFrameHANDSHAKE(handshake)
	if err := rw.WriteRecord(protocol.EncodeFrames([]protocol.Frame{hsFrame})); err != nil {
		stream.Close() //nolint:errcheck
		log.Error("[UDP_EXCHANGE] handshake write", "target", target, "err", err)
		return nil, fmt.Errorf("write handshake: %w", err)
	}

	aadC2S := crypto.BuildAAD("/v3/udp", salt, "c2s", "session", method)
	c2sEnc, c2sCounter, err := sk.Encryptor("c2s", "session", method)
	if err != nil {
		stream.Close() //nolint:errcheck
		return nil, fmt.Errorf("c2s session encryptor: %w", err)
	}
	c2sWriter := crypto.NewRecordWriter(stream, c2sEnc, c2sCounter, aadC2S)

	aadS2C := crypto.BuildAAD("/v3/udp", salt, "s2c", "session", method)
	s2cEnc, s2cCounter, err := sk.Encryptor("s2c", "session", method)
	if err != nil {
		stream.Close() //nolint:errcheck
		return nil, fmt.Errorf("s2c session encryptor: %w", err)
	}

	dr := crypto.NewDecryptedReader(stream, aadS2C, s2cEnc, s2cCounter)

	log.Debug("[UDP_EXCHANGE] opened", "target", target)
	return &UDPExchange{
		stream:   stream,
		tx:       shaper.NewLight(c2sWriter, h.shaperCfg),
		reader:   dr,
		target:   target,
		lastSeen: time.Now(),
	}, nil
}

func (ue *UDPExchange) Send(data []byte) error {
	ue.mu.Lock()
	defer ue.mu.Unlock()
	ue.lastSeen = time.Now()
	frame := protocol.NewFrameDATAGRAM(data)
	if err := ue.tx.PushFrame(frame); err != nil {
		return err
	}
	return ue.tx.Flush()
}

func (ue *UDPExchange) Receive() ([]byte, error) {
	frame, err := ue.reader.ReadFrame()
	if err != nil {
		return nil, err
	}
	ue.lastSeen = time.Now()
	switch frame.Type {
	case protocol.FrameDATAGRAM:
		return frame.Payload, nil
	case protocol.FrameFIN:
		return nil, io.EOF
	case protocol.FrameRST:
		return nil, fmt.Errorf("udp stream reset")
	default:
		return nil, fmt.Errorf("unexpected frame type: %d", frame.Type)
	}
}

func (ue *UDPExchange) Close() error {
	if ue.tx != nil {
		_ = ue.tx.Close()
	}
	return ue.stream.Close()
}

func (ue *UDPExchange) LastSeen() time.Time {
	ue.mu.Lock()
	defer ue.mu.Unlock()
	return ue.lastSeen
}
