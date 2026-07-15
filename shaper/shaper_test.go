package shaper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	easycrypto "github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/bytespool"
)

func TestBuildPaddingFrame(t *testing.T) {
	tests := []struct {
		name      string
		totalSize int
	}{
		{"tiny", 32},
		{"small", 256},
		{"medium", 700},
		{"large", 1600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame, ok := BuildPaddingFrame(tt.totalSize)
			if !ok {
				t.Fatal("expected padding frame to be produced")
			}
			if frame.Type != protocol.FramePADDING {
				t.Fatalf("expected PADDING frame, got %d", frame.Type)
			}
			if frame.Length == 0 {
				t.Fatal("padding frame length is 0")
			}
		})
	}
}

func TestBatchShaperFlushesBeforePlainRecordLimit(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("batch-limit-test-key")
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("1234567890123456")
	endpoint := "/v3/tcp"
	sk, err := easycrypto.NewStreamKeys(masterKey, salt, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	enc, ctr, err := sk.Encryptor("c2s", "session", protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	aad := easycrypto.BuildAAD(endpoint, salt, "c2s", "session", protocol.MethodAES256GCM)

	var out bytes.Buffer
	bs := New(easycrypto.NewRecordWriter(&out, enc, ctr, aad), Config{BatchWindowMS: 1000})
	payload := make([]byte, 16*1024)
	for range 4 {
		if err := bs.PushData(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := bs.Flush(); err != nil {
		t.Fatal(err)
	}

	decEnc, decCtr, err := sk.Encryptor("c2s", "session", protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	rr := easycrypto.NewRecordReader(&out, decEnc, decCtr, aad)
	records := 0
	for {
		plaintext, err := rr.ReadRecord()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(plaintext) > protocol.MaxPlainRecordSize {
			t.Fatalf("record plaintext size %d exceeds max %d", len(plaintext), protocol.MaxPlainRecordSize)
		}
		records++
	}
	if records != 2 {
		t.Fatalf("records = %d, want 2", records)
	}
}

func TestCoverInjectorSkipsDuringActiveStreaming(t *testing.T) {
	var injected []protocol.Frame
	var mu sync.Mutex
	closed := atomic.Bool{}

	ci := newCoverInjector(CoverConfig{
		BudgetRatio: 0.10,
		IdleTimeout: 50,
		MinSize:     64,
		MaxSize:     512,
		BudgetCap:   64 * 1024,
	}, func(f protocol.Frame) error {
		mu.Lock()
		injected = append(injected, f)
		mu.Unlock()
		return nil
	}, func() bool { return closed.Load() })
	if ci == nil {
		t.Fatal("expected non-nil coverInjector")
	}
	defer ci.stop()

	for range 100 {
		ci.addBudget(1024)
		time.Sleep(2 * time.Millisecond)
	}

	mu.Lock()
	count := len(injected)
	mu.Unlock()
	if count > 0 {
		t.Fatalf("expected 0 cover frames during active streaming, got %d", count)
	}

	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	count = len(injected)
	mu.Unlock()
	if count == 0 {
		t.Fatal("expected cover frames after idle period, got 0")
	}

	for _, f := range injected {
		if f.Type != protocol.FrameCOVER {
			t.Fatalf("expected COVER frame, got %v", f.Type)
		}
		bytespool.MustPut(f.Payload)
	}
}

func TestCoverInjectorFrameSizeRange(t *testing.T) {
	ci := &coverInjector{
		cfg: CoverConfig{MinSize: 128, MaxSize: 1500},
	}

	minSize, maxSize := ci.coverFrameSizeRange()
	if minSize != 128 {
		t.Fatalf("initial minSize = %d, want 128 (= cfg.MinSize)", minSize)
	}
	if maxSize != 509 {
		t.Fatalf("initial maxSize = %d, want 509", maxSize)
	}

	ci.totalSent.Store(1 << 20)
	minSize, maxSize = ci.coverFrameSizeRange()
	if minSize != 512 {
		t.Fatalf("at 1MB minSize = %d, want 512", minSize)
	}
	if maxSize != 1500 {
		t.Fatalf("at 1MB maxSize = %d, want cfg.MaxSize 1500", maxSize)
	}

	ci.totalSent.Store(10 << 20)
	minSize, maxSize = ci.coverFrameSizeRange()
	if minSize != 512 {
		t.Fatalf("at 10MB minSize = %d, want 512 (capped)", minSize)
	}
	if maxSize != 1500 {
		t.Fatalf("at 10MB maxSize = %d, want cfg.MaxSize 1500 (capped)", maxSize)
	}
}

func TestCoverInjectorFrameSizeRangeRespectsConfig(t *testing.T) {
	ci := &coverInjector{
		cfg: CoverConfig{MinSize: 256, MaxSize: 8192},
	}

	minSize, maxSize := ci.coverFrameSizeRange()
	if minSize != 256 {
		t.Fatalf("initial minSize = %d, want cfg.MinSize 256", minSize)
	}
	if maxSize != 2462 {
		t.Fatalf("initial maxSize = %d, want 2462", maxSize)
	}

	ci.totalSent.Store(1 << 20)
	minSize, maxSize = ci.coverFrameSizeRange()
	if minSize != 2478 {
		t.Fatalf("at 1MB minSize = %d, want 2478", minSize)
	}
	if maxSize != 8192 {
		t.Fatalf("at 1MB maxSize = %d, want cfg.MaxSize 8192", maxSize)
	}
}

func TestCoverInjectorStopsAfterThreshold(t *testing.T) {
	var injected []protocol.Frame
	var mu sync.Mutex
	closed := atomic.Bool{}

	ci := newCoverInjector(CoverConfig{
		BudgetRatio: 0.10,
		IdleTimeout: 50,
		MinSize:     64,
		MaxSize:     512,
		BudgetCap:   1 << 20,
	}, func(f protocol.Frame) error {
		mu.Lock()
		injected = append(injected, f)
		mu.Unlock()
		return nil
	}, func() bool { return closed.Load() })
	if ci == nil {
		t.Fatal("expected non-nil coverInjector")
	}
	defer ci.stop()

	for i := range 3000 {
		ci.addBudget(1024)
		_ = i
	}
	ci.mu.Lock()
	budgetBefore := ci.budget
	threshold := ci.coverThreshold
	ci.mu.Unlock()
	if threshold < int64(1024*1024) || threshold > int64(2*1024*1024) {
		t.Fatalf("coverThreshold = %d, want in [1MB, 2MB]", threshold)
	}

	// Verify stopped flag is set after exceeding threshold.
	if !ci.stopped.Load() {
		t.Fatal("expected stopped to be true after exceeding coverThreshold")
	}

	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	countDuringActive := len(injected)
	mu.Unlock()

	// addBudget after stopped should be a no-op.
	for i := range 3000 {
		ci.addBudget(1024)
		_ = i
	}

	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	countAfter := len(injected)
	mu.Unlock()

	_ = budgetBefore
	_ = countDuringActive
	if countAfter != countDuringActive {
		t.Fatalf("cover frames leaked after threshold: before=%d, after=%d", countDuringActive, countAfter)
	}

	mu.Lock()
	for _, f := range injected {
		bytespool.MustPut(f.Payload)
	}
	mu.Unlock()
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (lb *lockedBuffer) Write(p []byte) (int, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	return lb.buf.Write(p)
}

func (lb *lockedBuffer) Flush() {}

func (lb *lockedBuffer) Snapshot() []byte {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	out := make([]byte, lb.buf.Len())
	copy(out, lb.buf.Bytes())
	return out
}

func TestBatchShaperConcurrentFlushNoNonceDesync(t *testing.T) {
	const rounds = 20
	const goroutines = 4
	const pushesPerGoroutine = 50
	const payloadSize = 64

	masterKey, err := easycrypto.DeriveMasterKey("concurrent-flush-test-key")
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("1234567890123456")
	endpoint := "/v3/tcp"
	sk, err := easycrypto.NewStreamKeys(masterKey, salt, endpoint)
	if err != nil {
		t.Fatal(err)
	}

	totalPushes := goroutines * pushesPerGoroutine

	for round := range rounds {
		t.Run(fmt.Sprintf("round_%d", round), func(t *testing.T) {
			enc, ctr, err := sk.Encryptor("c2s", "session", protocol.MethodAES256GCM)
			if err != nil {
				t.Fatal(err)
			}
			aad := easycrypto.BuildAAD(endpoint, salt, "c2s", "session", protocol.MethodAES256GCM)

			out := &lockedBuffer{}
			bs := New(easycrypto.NewRecordWriter(out, enc, ctr, aad), Config{
				BatchWindowMS: 1,
				Cover: CoverConfig{
					BudgetRatio: 0.5,
					IdleTimeout: 5,
					MinSize:     64,
					MaxSize:     512,
					BudgetCap:   1 << 20,
				},
			})

			var wg sync.WaitGroup
			for g := range goroutines {
				wg.Add(1)
				go func(gid int) {
					defer wg.Done()
					for i := range pushesPerGoroutine {
						seq := uint32(gid*pushesPerGoroutine + i)
						payload := make([]byte, payloadSize)
						binary.BigEndian.PutUint32(payload[:4], seq)
						if err := bs.PushData(payload); err != nil {
							t.Errorf("PushData failed (goroutine %d, push %d): %v", gid, i, err)
							return
						}
					}
				}(g)
			}
			wg.Wait()

			if err := bs.Flush(); err != nil {
				t.Fatalf("Flush failed: %v", err)
			}
			if err := bs.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}

			decEnc, decCtr, err := sk.Encryptor("c2s", "session", protocol.MethodAES256GCM)
			if err != nil {
				t.Fatal(err)
			}
			rr := easycrypto.NewRecordReader(bytes.NewReader(out.Snapshot()), decEnc, decCtr, aad)

			seenSeqs := make(map[uint32]bool, totalPushes)
			recordCount := 0
			for {
				plaintext, err := rr.ReadRecord()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("record %d decrypt failed: %v", recordCount, err)
				}
				recordCount++

				r := bytes.NewReader(plaintext)
				for {
					frame, err := protocol.ReadFrame(r)
					if err != nil {
						if errors.Is(err, io.EOF) {
							break
						}
						t.Fatalf("decode frame failed in record %d: %v", recordCount-1, err)
					}
					if frame.Type == protocol.FrameDATA && len(frame.Payload) >= 4 {
						seq := binary.BigEndian.Uint32(frame.Payload[:4])
						if seenSeqs[seq] {
							t.Fatalf("duplicate sequence number %d in round %d", seq, round)
						}
						seenSeqs[seq] = true
					}
				}
			}

			if recordCount == 0 {
				t.Fatalf("no records decrypted in round %d", round)
			}

			for i := range totalPushes {
				if !seenSeqs[uint32(i)] {
					t.Fatalf("missing sequence number %d in round %d (got %d/%d)",
						i, round, len(seenSeqs), totalPushes)
				}
			}
		})
	}
}

type blockingWriter struct {
	inner      *lockedBuffer
	blocked    chan struct{}
	release    chan struct{}
	writeCount atomic.Int64
	blockOnce  sync.Once
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{
		inner:   &lockedBuffer{},
		blocked: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (bw *blockingWriter) Write(p []byte) (int, error) {
	bw.writeCount.Add(1)
	bw.blockOnce.Do(func() { close(bw.blocked) })
	<-bw.release
	return bw.inner.Write(p)
}

func (bw *blockingWriter) Flush() {}

type countingWriter struct {
	inner  *lockedBuffer
	writes atomic.Int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	cw.writes.Add(1)
	return cw.inner.Write(p)
}

func (cw *countingWriter) Flush() {}

func TestBatchShaperOnTimerInFlightDuringClose(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("close-race-on-timer")
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("1234567890123456")
	endpoint := "/v3/tcp"
	sk, err := easycrypto.NewStreamKeys(masterKey, salt, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	enc, ctr, err := sk.Encryptor("c2s", "session", protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	aad := easycrypto.BuildAAD(endpoint, salt, "c2s", "session", protocol.MethodAES256GCM)

	bw := newBlockingWriter()
	rw := easycrypto.NewRecordWriter(bw, enc, ctr, aad)
	bs := New(rw, Config{BatchWindowMS: 2})

	payload := make([]byte, 256)
	if err := bs.PushData(payload); err != nil {
		t.Fatal(err)
	}

	select {
	case <-bw.blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for onTimer to fire")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- bs.Close()
	}()

	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before onTimer was released: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(bw.release)

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Close to complete")
	}

	writesBefore := bw.writeCount.Load()
	time.Sleep(100 * time.Millisecond)
	if got := bw.writeCount.Load(); got != writesBefore {
		t.Fatalf("write after Close(): before=%d, after=%d", writesBefore, got)
	}

	if bw.writeCount.Load() == 0 {
		t.Fatal("expected at least one WriteRecord call")
	}
	decEnc, decCtr, err := sk.Encryptor("c2s", "session", protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	rr := easycrypto.NewRecordReader(bytes.NewReader(bw.inner.Snapshot()), decEnc, decCtr, aad)
	plaintext, err := rr.ReadRecord()
	if err != nil {
		t.Fatalf("failed to decrypt record: %v", err)
	}
	if len(plaintext) == 0 {
		t.Fatal("expected non-empty plaintext")
	}
	r := bytes.NewReader(plaintext)
	frame, err := protocol.ReadFrame(r)
	if err != nil {
		t.Fatalf("failed to read frame: %v", err)
	}
	if frame.Type != protocol.FrameDATA {
		t.Fatalf("expected DATA frame, got %v", frame.Type)
	}
	if len(frame.Payload) != len(payload) {
		t.Fatalf("payload size mismatch: got %d, want %d", len(frame.Payload), len(payload))
	}
}

func TestBatchShaperCoverInjectInFlightDuringClose(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("close-race-cover")
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("1234567890123456")
	endpoint := "/v3/tcp"
	sk, err := easycrypto.NewStreamKeys(masterKey, salt, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	enc, ctr, err := sk.Encryptor("c2s", "session", protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	aad := easycrypto.BuildAAD(endpoint, salt, "c2s", "session", protocol.MethodAES256GCM)

	bw := newBlockingWriter()
	rw := easycrypto.NewRecordWriter(bw, enc, ctr, aad)
	bs := New(rw, Config{BatchWindowMS: 10000})

	bigPayload := make([]byte, 58720)
	if err := bs.PushData(bigPayload); err != nil {
		t.Fatal(err)
	}

	coverPayload := bytespool.Get(256)[:256]
	coverFrame := protocol.Frame{
		Type:    protocol.FrameCOVER,
		Length:  256,
		Payload: coverPayload,
	}

	bsImpl := bs.(*batchShaper)
	go func() {
		_ = bsImpl.injectCoverFrame(coverFrame)
	}()

	select {
	case <-bw.blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for cover inject to trigger WriteRecord")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- bs.Close()
	}()

	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before cover inject was released: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(bw.release)

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Close to complete")
	}

	writesBefore := bw.writeCount.Load()
	time.Sleep(100 * time.Millisecond)
	if got := bw.writeCount.Load(); got != writesBefore {
		t.Fatalf("write after Close(): before=%d, after=%d", writesBefore, got)
	}

	if bw.writeCount.Load() == 0 {
		t.Fatal("expected at least one WriteRecord call")
	}
}

func TestBatchShaperNoWriteAfterClose(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("no-write-after-close")
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("1234567890123456")
	endpoint := "/v3/tcp"
	sk, err := easycrypto.NewStreamKeys(masterKey, salt, endpoint)
	if err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, 256)

	for i := range 100 {
		enc, ctr, err := sk.Encryptor("c2s", "session", protocol.MethodAES256GCM)
		if err != nil {
			t.Fatal(err)
		}
		aad := easycrypto.BuildAAD(endpoint, salt, "c2s", "session", protocol.MethodAES256GCM)

		cw := &countingWriter{inner: &lockedBuffer{}}
		rw := easycrypto.NewRecordWriter(cw, enc, ctr, aad)
		bs := New(rw, Config{BatchWindowMS: 1})

		if err := bs.PushData(payload); err != nil {
			t.Fatalf("PushData failed at iteration %d: %v", i, err)
		}
		if err := bs.Close(); err != nil {
			t.Fatalf("Close failed at iteration %d: %v", i, err)
		}

		writesAfter := cw.writes.Load()
		time.Sleep(10 * time.Millisecond)
		if got := cw.writes.Load(); got != writesAfter {
			t.Fatalf("write after close at iteration %d: before=%d, after=%d", i, writesAfter, got)
		}
	}
}
