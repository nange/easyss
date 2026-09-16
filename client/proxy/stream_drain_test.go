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

// drainMockStream 是一个 transport.Stream，其 Read 会阻塞直到 Close 被调用，
// 并带有可配置的 SlotDraining 判定结果，这样测试无需真实的 HTTP/2 传输层
// 即可覆盖中继的排空（drain）逻辑。
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

// newDrainHandler 构建一个使用较短 drain 空闲时间（让测试跑得快）的 StreamHandler，
// 以及中继在 stream 上所需的加密管线。
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

	c2sWriter, err := sk.NewWriter(stream, crypto.DirC2S, method)
	if err != nil {
		panic(err)
	}
	tx := shaper.New(c2sWriter, shaper.Config{})

	rx, err := sk.NewReader(stream, crypto.DirS2C, method)
	if err != nil {
		panic(err)
	}

	lc, lcPeer := net.Pipe()
	h := &StreamHandler{
		transport:         &mockTransport{},
		masterKey:         key,
		shaperCfg:         shaper.Config{},
		streamIdleTimeout: time.Minute, // 结束中继的必须是 drain，而不是空闲超时
		drainIdle:         drainIdle,
	}
	return h, tx, rx, lc, lcPeer
}

// TestStreamRelayDrainsIdleStreamOnDrainingSlot 验证端到端的 drain 接线：位于即将被
// 驱逐的 slot 上的流，在空闲超过 drain 宽限期后被中继提前关闭，报告为 idle-timeout
// 错误，并计入统计。
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

// TestStreamRelayKeepsIdleStreamOnHealthySlot 验证 slot 健康时 drain 永不触发：
// 中继远超 drain 宽限期仍然存活，只有流被外部关闭时才会结束。
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

	// 关闭流以干净地结束中继。
	_ = stream.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not end after the stream was closed")
	}
}
