package http2

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nange/easyss/v3/stats"
)

func newTestStream() (*http2Stream, *io.PipeReader) {
	pr, pw := io.Pipe()
	s := &http2Stream{
		w:         pw,
		respReady: make(chan struct{}),
		cancel:    func() {},
		done:      sync.OnceFunc(func() {}),
	}
	return s, pr
}

func TestHTTP2Stream_WriteSurfacesRoundTripErr(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	sentinel := errors.New("tls: handshake failure")
	s.setRoundTripErr(sentinel)

	// 关闭读取端，使下一次 Write 以 io.ErrClosedPipe 失败。
	pr.Close() //nolint:errcheck

	_, err := s.Write([]byte("payload"))
	if err == nil {
		t.Fatal("expected error from Write, got nil")
	}
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("expected error to wrap io.ErrClosedPipe, got: %v", err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected error to wrap sentinel error, got: %v", err)
	}
}

func TestHTTP2Stream_WriteNoRoundTripErr(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	// rtErr 保持 nil——Write 应返回裸的 io.ErrClosedPipe。
	pr.Close() //nolint:errcheck

	_, err := s.Write([]byte("payload"))
	if err == nil {
		t.Fatal("expected error from Write, got nil")
	}
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("expected io.ErrClosedPipe, got: %v", err)
	}
	if err != io.ErrClosedPipe {
		t.Errorf("expected bare io.ErrClosedPipe (no wrapping), got: %v", err)
	}
}

func TestHTTP2Stream_WriteSuccess(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 16)
		n, err := pr.Read(buf)
		if err != nil {
			t.Errorf("unexpected read error: %v", err)
			return
		}
		if string(buf[:n]) != "hello" {
			t.Errorf("read = %q, want %q", buf[:n], "hello")
		}
	}()

	n, err := s.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 5 {
		t.Errorf("write count = %d, want 5", n)
	}
	<-done
}

func TestSetRoundTripErr_Concurrent(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			s.setRoundTripErr(errors.New("concurrent error"))
		})
	}
	wg.Wait()

	s.rtErrMu.Lock()
	if s.rtErr == nil {
		t.Error("expected rtErr to be set after concurrent calls")
	}
	s.rtErrMu.Unlock()
}

// TestHTTP2Stream_ConnBytesCountsBothDirections 验证连接轮换字节计数器
// 同时累计上传与下载字节：针对 conn_max_bytes 的轮换必须对纯上传流量
// 也生效，因为中间盒按任一方向的总字节数限流。
func TestHTTP2Stream_ConnBytesCountsBothDirections(t *testing.T) {
	slot := &transportSlot{}
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck
	s.slot = slot
	s.startTime = time.Now()

	s.trackRead(1000)
	s.trackWrite(2000)

	if got := slot.connBytes.Load(); got != 3000 {
		t.Fatalf("connBytes = %d, want 3000 (both directions)", got)
	}
	// 吞吐健康样本保持仅下载口径：bytesRecv 不得包含上传字节。
	if got := slot.bytesRecv.Load(); got != 1000 {
		t.Fatalf("bytesRecv = %d, want 1000 (download only)", got)
	}
}

// TestHTTP2Stream_TrackWriteNilSlotNoOp 守护 trackWrite 在开始统计连接
// 字节之后的 nil 槽位快路径。
func TestHTTP2Stream_TrackWriteNilSlotNoOp(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	s.trackWrite(1 << 20) // 不得 panic

	if s.heavyState.Load() != heavyIdle {
		t.Fatal("nil slot must not mark heavy")
	}
}

// TestHTTP2Stream_RecordsPathRTTOnResponse 验证 MarkBootstrapSent 之后
// 到达的成功响应会贡献一个纯路径 RTT 样本（bootstrap 记录刷出 ->
// 响应头到达），而从未盖章的流保持静默。
func TestHTTP2Stream_RecordsPathRTTOnResponse(t *testing.T) {
	newStream := func() *http2Stream {
		s, pr := newTestStream()
		_ = pr
		return s
	}

	t.Run("stamped stream records the sample", func(t *testing.T) {
		stats.ResetCounters()
		s := newStream()
		defer s.Close() //nolint:errcheck

		s.MarkBootstrapSent()
		time.Sleep(2 * time.Millisecond)
		s.deliver(roundTripResult{
			resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))},
			err:  nil,
		})

		buf := make([]byte, 16)
		if _, err := s.Read(buf); err != io.EOF {
			t.Fatalf("Read = %v, want io.EOF", err)
		}

		snap := stats.Collect()
		if snap.RTTCount != 1 {
			t.Fatalf("RTTCount = %d, want 1", snap.RTTCount)
		}
		if snap.AvgRTT() < time.Millisecond {
			t.Fatalf("AvgRTT = %v, want >= 1ms", snap.AvgRTT())
		}
	})

	t.Run("unstamped stream records nothing", func(t *testing.T) {
		stats.ResetCounters()
		s := newStream()
		defer s.Close() //nolint:errcheck

		s.deliver(roundTripResult{
			resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))},
			err:  nil,
		})

		buf := make([]byte, 16)
		if _, err := s.Read(buf); err != io.EOF {
			t.Fatalf("Read = %v, want io.EOF", err)
		}

		if got := stats.Collect().RTTCount; got != 0 {
			t.Fatalf("RTTCount = %d, want 0 without MarkBootstrapSent", got)
		}
	})
}

// TestHTTP2Stream_SlotDraining 验证排空信号反映槽位的驱逐标记
// （expiring/degraded），它驱动代理对空闲流的提前关闭
// （relay.BidirectionalWithDrain）。
func TestHTTP2Stream_SlotDraining(t *testing.T) {
	s, pr := newTestStream()
	defer pr.Close() //nolint:errcheck
	defer s.Close()  //nolint:errcheck

	slot := &transportSlot{}
	s.slot = slot

	if s.SlotDraining() {
		t.Fatal("fresh slot must not report draining")
	}
	slot.expiring.Store(true)
	if !s.SlotDraining() {
		t.Fatal("expected draining when the slot is expiring")
	}
	slot.expiring.Store(false)
	slot.degraded.Store(true)
	if !s.SlotDraining() {
		t.Fatal("expected draining when the slot is degraded")
	}
	slot.expiring.Store(true)
	if !s.SlotDraining() {
		t.Fatal("expected draining when the slot is expiring+degraded")
	}

	// 没有槽位的流不得 panic，也永不排空。
	ns := &http2Stream{}
	if ns.SlotDraining() {
		t.Fatal("nil slot must not report draining")
	}
}
