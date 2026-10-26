package proxy

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/transport"
)

// stallingStream 模拟传输层背压：第一次写开始后一直阻塞到 Close。
// Close 关闭 release，使阻塞的写按 http2Stream 的语义返回 net.ErrClosed。
type stallingStream struct {
	mu        sync.Mutex
	closed    bool
	writeOnce sync.Once
	writing   chan struct{}
	release   chan struct{}
	closedCh  chan struct{}
}

func newStallingStream() *stallingStream {
	return &stallingStream{
		writing:  make(chan struct{}),
		release:  make(chan struct{}),
		closedCh: make(chan struct{}),
	}
}

func (s *stallingStream) Read([]byte) (int, error) { return 0, io.EOF }

func (s *stallingStream) Write([]byte) (int, error) {
	s.writeOnce.Do(func() { close(s.writing) })
	<-s.release
	return 0, net.ErrClosed
}

func (s *stallingStream) CloseWrite() error { return nil }

func (s *stallingStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.release)
		close(s.closedCh)
	}
	return nil
}

var _ transport.Stream = (*stallingStream)(nil)

// recordingStream 记录全部密文，Close 后仍可读回，用于断言收尾记录。
type recordingStream struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func (s *recordingStream) Read([]byte) (int, error) { return 0, io.EOF }

func (s *recordingStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, net.ErrClosed
	}
	return s.buf.Write(p)
}

func (s *recordingStream) CloseWrite() error { return nil }

func (s *recordingStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *recordingStream) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.buf.Bytes())
}

func newTestUDPExchange(t *testing.T, stream transport.Stream) (*UDPExchange, *crypto.StreamKeys) {
	t.Helper()
	masterKey, err := crypto.DeriveMasterKey("udp-close-test")
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	sk, err := crypto.NewStreamKeys(masterKey, []byte("1234567890123456"), config.EndpointUDP)
	if err != nil {
		t.Fatalf("NewStreamKeys: %v", err)
	}
	rw, err := sk.NewWriter(stream, crypto.DirC2S, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	return &UDPExchange{
		stream: stream,
		tx:     shaper.New(rw, shaper.Config{BatchWindowMS: 10}),
		target: "example.com:53",
	}, sk
}

// 传输层背压时写记录会占住 shaper 的写锁；Close 不能等它排空，且关流本身也可能
// 阻塞在连接写锁上，所以必须把阻塞的写解开并在预算内返回。
func TestUDPExchangeCloseReturnsWhenWriteIsBlocked(t *testing.T) {
	stream := newStallingStream()
	ue, _ := newTestUDPExchange(t, stream)

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		for range 16 {
			if err := ue.Send(make([]byte, protocol.MaxUDPDataSize)); err != nil {
				return
			}
		}
	}()

	select {
	case <-stream.writing:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for a shaper write to block")
	}

	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		_ = ue.Close()
	}()

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked behind the shaper write lock")
	}

	select {
	case <-stream.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("stream was not closed after Close returned")
	}

	select {
	case <-sendDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Send did not return after the stream was closed")
	}
}

// 正常收尾必须把 FIN 冲刷出去：服务端依靠它立即回收 UDP 关联。
func TestUDPExchangeCloseFlushesFIN(t *testing.T) {
	stream := &recordingStream{}
	ue, sk := newTestUDPExchange(t, stream)

	payload := []byte("dns query")
	if err := ue.Send(payload); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := ue.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rr, err := sk.NewReader(bytes.NewReader(stream.bytes()), crypto.DirC2S, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	var frames []protocol.Frame
	for {
		frame, err := rr.ReadFrame()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("ReadFrame: %v", err)
		}
		frames = append(frames, frame)
	}
	seenFIN := false
	for _, frame := range frames {
		if frame.Type == protocol.FrameFIN {
			seenFIN = true
		}
	}
	if len(frames) < 2 || frames[0].Type != protocol.FrameDATAGRAM || !seenFIN {
		t.Fatalf("unexpected frames: %+v", frames)
	}
}
