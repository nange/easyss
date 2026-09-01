package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/stats"
)

// drainMockStream is a transport.Stream whose Read blocks until Close, with
// a configurable SlotDraining verdict, so tests can exercise the relay drain
// without a real HTTP/2 transport.
type drainMockStream struct {
	slotDraining bool
	closedCh     chan struct{}
	closeOnce    sync.Once
}

func newDrainMockStream(slotDraining bool) *drainMockStream {
	return &drainMockStream{slotDraining: slotDraining, closedCh: make(chan struct{})}
}

func (s *drainMockStream) Read(p []byte) (int, error) {
	<-s.closedCh
	return 0, io.ErrClosedPipe
}

func (s *drainMockStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *drainMockStream) CloseWrite() error           { return nil }
func (s *drainMockStream) Close() error {
	s.closeOnce.Do(func() { close(s.closedCh) })
	return nil
}

func (s *drainMockStream) SlotDraining() bool { return s.slotDraining }

func (s *drainMockStream) closed() bool {
	select {
	case <-s.closedCh:
		return true
	default:
		return false
	}
}

// newDrainHandler builds a StreamHandler with a short drain idle (so tests
// run fast) plus the crypto plumbing a relay needs over stream.
func newDrainHandler(stream *drainMockStream, drainIdle time.Duration) (*StreamHandler, shaper.Shaper, *crypto.DecryptedReader, net.Conn, net.Conn) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	endpoint := config.EndpointTCP
	method := protocol.MethodAES256GCM

	salt, err := crypto.GenerateSalt()
	if err != nil {
		panic(err)
	}
	sk, err := crypto.NewStreamKeys(key, salt, endpoint)
	if err != nil {
		panic(err)
	}

	aadC2S := crypto.BuildAAD(endpoint, salt, "c2s", "session", method)
	c2sEnc, c2sCounter, err := sk.Encryptor("c2s", "session", method)
	if err != nil {
		panic(err)
	}
	tx := shaper.New(crypto.NewRecordWriter(stream, c2sEnc, c2sCounter, aadC2S), shaper.Config{})

	aadS2C := crypto.BuildAAD(endpoint, salt, "s2c", "session", method)
	s2cEnc, s2cCounter, err := sk.Encryptor("s2c", "session", method)
	if err != nil {
		panic(err)
	}
	rx := crypto.NewDecryptedReader(stream, aadS2C, s2cEnc, s2cCounter)

	lc, lcPeer := net.Pipe()
	h := &StreamHandler{
		transport:         &mockTransport{},
		masterKey:         key,
		shaperCfg:         shaper.Config{},
		streamIdleTimeout: time.Minute, // the drain, not the idle timeout, must end the relay
		drainIdle:         drainIdle,
	}
	return h, tx, rx, lc, lcPeer
}

// TestStreamRelayDrainsIdleStreamOnDrainingSlot verifies the end-to-end drain
// wiring: a stream on a slot due for eviction that sits idle past the drain
// grace is closed early by the relay, reported as an idle-timeout error and
// counted in the stats.
func TestStreamRelayDrainsIdleStreamOnDrainingSlot(t *testing.T) {
	stats.ResetCounters()
	stream := newDrainMockStream(true)
	h, tx, rx, lc, lcPeer := newDrainHandler(stream, 100*time.Millisecond)
	defer lcPeer.Close() //nolint:errcheck

	done := make(chan error, 1)
	go func() { done <- h.relay("example.com:443", lc, tx, rx, stream) }()

	select {
	case err := <-done:
		if !errors.Is(err, ErrStreamIdleTimeout) {
			t.Fatalf("expected ErrStreamIdleTimeout (drained), got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not drain the idle stream in time")
	}
	if !stream.closed() {
		t.Fatal("expected the stream to be closed by the drain")
	}
	if got := stats.Collect().StreamsDrained; got != 1 {
		t.Fatalf("StreamsDrained = %d, want 1", got)
	}
}

// TestStreamRelayKeepsIdleStreamOnHealthySlot verifies the drain never fires
// while the slot is healthy: the relay survives far beyond the drain grace
// and only ends when the stream is closed externally.
func TestStreamRelayKeepsIdleStreamOnHealthySlot(t *testing.T) {
	stream := newDrainMockStream(false)
	h, tx, rx, lc, lcPeer := newDrainHandler(stream, 100*time.Millisecond)
	defer lcPeer.Close() //nolint:errcheck

	done := make(chan error, 1)
	go func() { done <- h.relay("example.com:443", lc, tx, rx, stream) }()

	select {
	case err := <-done:
		t.Fatalf("relay ended early on a healthy slot: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if stream.closed() {
		t.Fatal("stream must not be closed while the slot is healthy")
	}

	// Close the stream to end the relay cleanly.
	_ = stream.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not end after the stream was closed")
	}
}
