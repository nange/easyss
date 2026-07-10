package shaper

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	easycrypto "github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/bytespool"
)

func TestBuildPaddingFrames(t *testing.T) {
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
			frames := BuildPaddingFrames(tt.totalSize)
			if len(frames) > 1 {
				t.Fatalf("expected at most 1 padding frame, got %d", len(frames))
			}
			if len(frames) == 1 {
				if frames[0].Type != protocol.FramePADDING {
					t.Fatalf("expected PADDING frame, got %d", frames[0].Type)
				}
				if int(frames[0].Length) == 0 {
					t.Fatal("padding frame length is 0")
				}
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
		cfg: CoverConfig{MinSize: 64, MaxSize: 1500},
	}

	minSize, maxSize := ci.coverFrameSizeRange()
	if minSize != 64 || maxSize != 512 {
		t.Fatalf("initial range = [%d, %d], want [64, 512]", minSize, maxSize)
	}

	ci.totalSent.Store(1 << 20)
	minSize, maxSize = ci.coverFrameSizeRange()
	if minSize != 256 || maxSize != 1500 {
		t.Fatalf("at 1MB range = [%d, %d], want [256, 1500]", minSize, maxSize)
	}

	ci.totalSent.Store(10 << 20)
	minSize, maxSize = ci.coverFrameSizeRange()
	if minSize != 256 || maxSize != 1500 {
		t.Fatalf("at 10MB range = [%d, %d], want [256, 1500] (capped)", minSize, maxSize)
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
