package shaper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sharedconfig "github.com/nange/easyss/v3/config"
	easycrypto "github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/bytespool"
)

// TestConfigNormalize 固定了整形器默认值和边界的唯一出处，
// 这些值过去曾被客户端配置层、服务端 handler 和 New 各自重复应用。
func TestConfigNormalize(t *testing.T) {
	got := Config{}.Normalize()
	if got.BatchWindowMS != sharedconfig.DefaultBatchWindowMS {
		t.Errorf("BatchWindowMS = %d, want %d", got.BatchWindowMS, sharedconfig.DefaultBatchWindowMS)
	}
	if got.Cover.BudgetRatio != sharedconfig.DefaultCoverBudgetRatio {
		t.Errorf("BudgetRatio = %v, want %v", got.Cover.BudgetRatio, sharedconfig.DefaultCoverBudgetRatio)
	}
	if got.Cover.BudgetCap != sharedconfig.DefaultCoverBudgetCap {
		t.Errorf("BudgetCap = %d, want %d", got.Cover.BudgetCap, sharedconfig.DefaultCoverBudgetCap)
	}
	if got.Cover.IdleTimeout != defaultCoverIdleTimeoutMS {
		t.Errorf("IdleTimeout = %d, want %d", got.Cover.IdleTimeout, defaultCoverIdleTimeoutMS)
	}
	if got.Cover.MinSize != defaultCoverMinSize || got.Cover.MaxSize != defaultCoverMaxSize {
		t.Errorf("size range = [%d,%d], want [%d,%d]", got.Cover.MinSize, got.Cover.MaxSize, defaultCoverMinSize, defaultCoverMaxSize)
	}

	capped := Config{
		BatchWindowMS: 100,
		Cover:         CoverConfig{BudgetRatio: 2, BudgetCap: -1, IdleTimeout: -5},
	}.Normalize()
	if capped.BatchWindowMS != maxBatchWindowMS {
		t.Errorf("BatchWindowMS = %d, want %d", capped.BatchWindowMS, maxBatchWindowMS)
	}
	if capped.Cover.BudgetRatio != sharedconfig.DefaultCoverBudgetRatio {
		t.Errorf("BudgetRatio = %v, want the default", capped.Cover.BudgetRatio)
	}
	if capped.Cover.BudgetCap != sharedconfig.DefaultCoverBudgetCap {
		t.Errorf("BudgetCap = %d, want the default", capped.Cover.BudgetCap)
	}
	if capped.Cover.IdleTimeout != defaultCoverIdleTimeoutMS {
		t.Errorf("IdleTimeout = %d, want the default", capped.Cover.IdleTimeout)
	}

	// 范围内的值保持不变。
	kept := Config{BatchWindowMS: 7, Cover: CoverConfig{BudgetRatio: 0.5, BudgetCap: 4096}}.Normalize()
	if kept.BatchWindowMS != 7 || kept.Cover.BudgetRatio != 0.5 || kept.Cover.BudgetCap != 4096 {
		t.Errorf("in-range values changed: %+v", kept)
	}
}

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
			frame, ok := BuildPaddingFrame(tt.totalSize, 0)
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

// TestBuildPaddingFrameBudget 固定 budget 的语义：它是"这条记录可用的总空间"，
// 填充放不下时返回 false，而不是生成一个会撑爆调用方缓冲区的帧。
// 整形器用当前容量做预算，从而避免"为了填充而把缓冲区从 4KB 撑到 64KB"。
func TestBuildPaddingFrameBudget(t *testing.T) {
	// 700 字节的记录会被填充到 1500~2000 字节区间（见 computePadPayloadSize），
	// 因此 800 一定放不下、4096 一定放得下。
	if _, ok := BuildPaddingFrame(700, 800); ok {
		t.Fatal("budget 不足时不应产生填充")
	}
	if _, ok := BuildPaddingFrame(700, 4096); !ok {
		t.Fatal("budget 充足时应产生填充")
	}
	// 预算超过线上格式上限时按上限处理，不 panic、不越界。
	if _, ok := BuildPaddingFrame(700, 1<<20); !ok {
		t.Fatal("budget 超限时应退化为按线上上限判断")
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

	var out bytes.Buffer
	bs := New(newTestWriter(t, sk, &out), Config{BatchWindowMS: 1000})
	// 提前登记补偿关闭：PushData/Flush 中途失败时也不能把活着的注入器与定时器
	// 留给后面的测试。
	t.Cleanup(func() { _ = bs.Close() })
	payload := make([]byte, 16*1024)
	for range 4 {
		if err := bs.PushData(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := bs.Flush(); err != nil {
		t.Fatal(err)
	}
	// 读取 out 之前必须先冻结写入端：整形器不关闭时，cover 注入器会在空闲后注入
	// 帧并重新武装批处理定时器，把新记录写回同一个 bytes.Buffer。写入端与读取端
	// 共享一个无锁 buffer 且二者之间没有 happens-before，2026-09-30 macOS 的
	// -race job 就是这样在后续测试里报出 DATA RACE 的。Close 同时冲刷尾部记录，
	// 因此记录流与只调用 Flush 时完全一致。
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}

	rr := newTestReader(t, sk, &out)
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

// TestBatchShaperStartsWithMinimalBuffer 固定"空闲流只占最小缓冲区"这一内存
// 契约：服务端内存占用 ≈ 峰值并发流数 × 每流缓冲区大小，而常驻连接、心跳流
// 与探测流在数量上占绝大多数，它们绝不能各自预留一整块记录缓冲区。
func TestBatchShaperStartsWithMinimalBuffer(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("batch-min-buffer")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := easycrypto.NewStreamKeys(masterKey, []byte("1234567890123456"), "/v3/tcp")
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	bs := New(newTestWriter(t, sk, &out), Config{BatchWindowMS: 1000})
	t.Cleanup(func() { _ = bs.Close() })

	impl := bs.(*batchShaper)
	impl.mu.Lock()
	got := cap(impl.plaintext)
	impl.mu.Unlock()
	if got != protocol.MinRecordBufferSize {
		t.Fatalf("新流的明文缓冲区 cap = %d, want %d", got, protocol.MinRecordBufferSize)
	}

	// 只推入少量数据不应触发增长：4KB 之内都属于"小事物流"。
	impl.mu.Lock()
	err = impl.appendFrameLocked(protocol.FrameDATA, make([]byte, 512), false)
	grown := cap(impl.plaintext)
	impl.mu.Unlock()
	if err != nil {
		t.Fatalf("appendFrameLocked: %v", err)
	}
	if grown != protocol.MinRecordBufferSize {
		t.Fatalf("推入 512B 后 cap = %d, want %d（不应增长）", grown, protocol.MinRecordBufferSize)
	}
}

// TestBatchShaperBufferGrowsOnDemand 固定按需增长的边界与归还：
// 攒够数据后缓冲区必须增长（否则 AppendFrame 会自行 realloc 而绕过 BufferPool），
// 且任何时刻都不会超过 protocol.MaxPlainRecordSize。
func TestBatchShaperBufferGrowsOnDemand(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("batch-grow")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := easycrypto.NewStreamKeys(masterKey, []byte("1234567890123456"), "/v3/tcp")
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	bs := New(newTestWriter(t, sk, &out), Config{BatchWindowMS: 1000})
	t.Cleanup(func() { _ = bs.Close() })
	impl := bs.(*batchShaper)

	// 单帧 32KB 超过初始 4KB，必须增长到足以容纳它（并带上帧头）。
	if err := bs.PushData(make([]byte, 32*1024)); err != nil {
		t.Fatalf("PushData: %v", err)
	}
	impl.mu.Lock()
	grown := cap(impl.plaintext)
	impl.mu.Unlock()
	if grown < 32*1024+protocol.FrameHeaderSize {
		t.Fatalf("推入 32KB 后 cap = %d，不足以容纳该帧", grown)
	}
	if grown > protocol.MaxPlainRecordSize {
		t.Fatalf("cap = %d 超过上限 %d", grown, protocol.MaxPlainRecordSize)
	}

	// 持续推入直到出现冲刷，验证缓冲区在来回冲刷之后仍然受上限约束。
	// 关键是 Bytes() 与 cap 都不能失控：增长按 2 倍摊销，不能每帧都重新分配。
	for range 8 {
		if err := bs.PushData(make([]byte, 16*1024)); err != nil {
			t.Fatalf("PushData: %v", err)
		}
		impl.mu.Lock()
		cur := cap(impl.plaintext)
		impl.mu.Unlock()
		if cur > protocol.MaxPlainRecordSize {
			t.Fatalf("冲刷后 cap = %d 超过上限 %d", cur, protocol.MaxPlainRecordSize)
		}
	}
	if err := bs.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	impl.mu.Lock()
	afterFlush := cap(impl.plaintext)
	impl.mu.Unlock()
	if afterFlush != protocol.MinRecordBufferSize {
		t.Fatalf("冲刷后 cap = %d, want %d（大缓冲区应换回初始大小）", afterFlush, protocol.MinRecordBufferSize)
	}
}

// TestBatchShaperAcceptsLargeDatagramFrame 固定单帧上限仍是线上格式上限：
// UDP 数据报帧最大可达 protocol.MaxUDPDataSize(65507)，它超过批处理的冲刷
// 阈值，但必须被当作合法帧接受（历史缺陷：用阈值去做尺寸校验会把它判成错误）。
func TestBatchShaperAcceptsLargeDatagramFrame(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("batch-large-datagram")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := easycrypto.NewStreamKeys(masterKey, []byte("1234567890123456"), "/v3/tcp")
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	bs := New(newTestWriter(t, sk, &out), Config{BatchWindowMS: 1000})
	t.Cleanup(func() { _ = bs.Close() })

	// 60000 字节：小于 MaxUDPDataSize，但远大于 flushThreshold。
	payload := make([]byte, 60000)
	if err := bs.PushData(payload); err != nil {
		t.Fatalf("PushData(60000B): %v", err)
	}

	// 单帧超过 MaxPlainRecordSize 时仍必须被拒绝（线上格式的 3 字节长度前缀
	// 虽能表达更大值，但解码端的上限是 protocol.MaxPlainRecordSize）。
	if err := bs.PushData(make([]byte, protocol.MaxPlainRecordSize+1)); err == nil {
		t.Fatal("超过 MaxPlainRecordSize 的帧应被拒绝")
	}
}

// TestCoverNormalizeClampsFrameSize 验证 Config.Normalize 会将配置错误的
// cover 尺寸钳制到线缆格式上限，使过大的 MaxSize 不会产生截断的 uint16
// 长度或 bytespool.Get 的 nil panic payload。
// Normalize 在 New 的开头运行，先于注入器的构建。
func TestCoverNormalizeClampsFrameSize(t *testing.T) {
	cfg := Config{Cover: CoverConfig{
		BudgetRatio: 0.10,
		MinSize:     200_000, // > 65535 且 > bytespool 上限
		MaxSize:     1_000_000,
		BudgetCap:   2_000_000,
	}}.Normalize()

	if cfg.Cover.MinSize > protocol.MaxUDPDataSize || cfg.Cover.MaxSize > protocol.MaxUDPDataSize {
		t.Fatalf("cover size range not clamped: min=%d max=%d", cfg.Cover.MinSize, cfg.Cover.MaxSize)
	}
	if cfg.Cover.MaxSize < cfg.Cover.MinSize {
		t.Fatalf("MaxSize %d < MinSize %d after clamping", cfg.Cover.MaxSize, cfg.Cover.MinSize)
	}

	ci := newCoverInjector(cfg.Cover, func(protocol.Frame) error { return nil }, func() bool { return false })
	if ci == nil {
		t.Fatal("expected non-nil coverInjector")
	}
	defer ci.stop()

	minSize, maxSize := ci.coverFrameSizeRange()
	if minSize > protocol.MaxUDPDataSize || maxSize > protocol.MaxUDPDataSize {
		t.Fatalf("cover size range not clamped: min=%d max=%d", minSize, maxSize)
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

	// 在锁下做快照。注入器会一直按空闲定时器触发，直到 ci.stop() 执行，
	// 因此直接遍历共享切片会与注入回调中的 append 产生竞争；
	// 若跨 t.Fatalf 持有 mu，则会使互斥锁永远保持锁定。
	mu.Lock()
	frames := slices.Clone(injected)
	mu.Unlock()

	for _, f := range frames {
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

func TestCoverInjectorKeepsInjectingAfterLargeTraffic(t *testing.T) {
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

	// 喂入远超旧的累计停止阈值（2-3MB）的数据；cover 必须持续流动，
	// 受预算限制，而不是突然停止。
	for i := range 3200 {
		ci.addBudget(1024)
		_ = i
	}
	if ci.stopped.Load() {
		t.Fatal("cover injector unexpectedly stopped")
	}

	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	countFirst := len(injected)
	mu.Unlock()
	if countFirst == 0 {
		t.Fatal("expected cover frames after idle period, got 0")
	}

	// 更多真实流量：cover 应继续流动，而不是逐渐消失。
	for i := range 3000 {
		ci.addBudget(1024)
		_ = i
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	countAfter := len(injected)
	mu.Unlock()
	if countAfter <= countFirst {
		t.Fatalf("cover frames stopped after large traffic: before=%d, after=%d", countFirst, countAfter)
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

			out := &lockedBuffer{}
			bs := New(newTestWriter(t, sk, out), Config{
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

			rr := newTestReader(t, sk, bytes.NewReader(out.Snapshot()))

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

				remaining := plaintext
				for len(remaining) > 0 {
					frame, n, err := protocol.DecodeFrame(remaining)
					if err != nil {
						t.Fatalf("decode frame failed in record %d: %v", recordCount-1, err)
					}
					remaining = remaining[n:]
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

	bw := newBlockingWriter()
	rw := newTestWriter(t, sk, bw)
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
	rr := newTestReader(t, sk, bytes.NewReader(bw.inner.Snapshot()))
	plaintext, err := rr.ReadRecord()
	if err != nil {
		t.Fatalf("failed to decrypt record: %v", err)
	}
	if len(plaintext) == 0 {
		t.Fatal("expected non-empty plaintext")
	}
	frame, _, err := protocol.DecodeFrame(plaintext)
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

	bw := newBlockingWriter()
	rw := newTestWriter(t, sk, bw)
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

		cw := &countingWriter{inner: &lockedBuffer{}}
		rw := newTestWriter(t, sk, cw)
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

func TestIsClosedStreamError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "wrapped http2 stream closed",
			err:  fmt.Errorf("crypto: write record: %w", errors.New("http2: stream closed")),
			want: true,
		},
		{
			name: "wrapped io.ErrClosedPipe",
			err:  fmt.Errorf("wrapped: %w", io.ErrClosedPipe),
			want: true,
		},
		{
			name: "net.ErrClosed",
			err:  net.ErrClosed,
			want: true,
		},
		{
			name: "plain error",
			err:  errors.New("boom"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isClosedStreamError(tt.err); got != tt.want {
				t.Fatalf("isClosedStreamError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// newTestWriter 通过生产外观构建 c2s 会话记录写入器，
// 取代了测试过去手工拼装的 Encryptor + BuildAAD + NewRecordWriter 组合。
func newTestWriter(t *testing.T, sk *easycrypto.StreamKeys, w io.Writer) *easycrypto.RecordWriter {
	t.Helper()
	rw, err := sk.NewWriter(w, easycrypto.DirC2S, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	return rw
}

// newTestReader 是 newTestWriter 对应的读取器版本。
func newTestReader(t *testing.T, sk *easycrypto.StreamKeys, r io.Reader) *easycrypto.RecordReader {
	t.Helper()
	rr, err := sk.NewRecordReader(r, easycrypto.DirC2S, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
