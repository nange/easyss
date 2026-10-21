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
	"github.com/nange/easyss/v3/util/netbuf"
)

// 防回归：整形器的默认值与边界只由 Config.Normalize 一处给出。
func TestConfigNormalize(t *testing.T) {
	got := Config{}.Normalize()
	if got.BatchWindowMS != sharedconfig.DefaultBatchWindowMS {
		t.Errorf("BatchWindowMS = %d, want %d", got.BatchWindowMS, sharedconfig.DefaultBatchWindowMS)
	}
	if got.BudgetRatio != sharedconfig.DefaultCoverBudgetRatio {
		t.Errorf("BudgetRatio = %v, want %v", got.BudgetRatio, sharedconfig.DefaultCoverBudgetRatio)
	}
	if got.BudgetCap != sharedconfig.DefaultCoverBudgetCap {
		t.Errorf("BudgetCap = %d, want %d", got.BudgetCap, sharedconfig.DefaultCoverBudgetCap)
	}
	if got.IdleTimeout != defaultCoverIdleTimeoutMS {
		t.Errorf("IdleTimeout = %d, want %d", got.IdleTimeout, defaultCoverIdleTimeoutMS)
	}
	if got.MinSize != defaultCoverMinSize || got.MaxSize != defaultCoverMaxSize {
		t.Errorf("size range = [%d,%d], want [%d,%d]", got.MinSize, got.MaxSize, defaultCoverMinSize, defaultCoverMaxSize)
	}

	capped := Config{
		BatchWindowMS: 100,
		BudgetRatio:   2,
		BudgetCap:     -1,
		IdleTimeout:   -5,
	}.Normalize()
	if capped.BatchWindowMS != maxBatchWindowMS {
		t.Errorf("BatchWindowMS = %d, want %d", capped.BatchWindowMS, maxBatchWindowMS)
	}
	if capped.BudgetRatio != sharedconfig.DefaultCoverBudgetRatio {
		t.Errorf("BudgetRatio = %v, want the default", capped.BudgetRatio)
	}
	if capped.BudgetCap != sharedconfig.DefaultCoverBudgetCap {
		t.Errorf("BudgetCap = %d, want the default", capped.BudgetCap)
	}
	if capped.IdleTimeout != defaultCoverIdleTimeoutMS {
		t.Errorf("IdleTimeout = %d, want the default", capped.IdleTimeout)
	}

	kept := Config{BatchWindowMS: 7, BudgetRatio: 0.5, BudgetCap: 4096}.Normalize()
	if kept.BatchWindowMS != 7 || kept.BudgetRatio != 0.5 || kept.BudgetCap != 4096 {
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

// budget 是这条记录可用的总空间，放不下时返回 false；用当前容量做预算，
// 避免为了填充把缓冲区从 4KB 撑到 64KB。
func TestBuildPaddingFrameBudget(t *testing.T) {
	// 700 字节的记录会被填充到 1500~2000 区间（见 computePadPayloadSize），800 放不下、4096 放得下。
	if _, ok := BuildPaddingFrame(700, 800); ok {
		t.Fatal("budget 不足时不应产生填充")
	}
	if _, ok := BuildPaddingFrame(700, 4096); !ok {
		t.Fatal("budget 充足时应产生填充")
	}
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
	// 提前登记补偿关闭：PushData/Flush 中途失败时也不能把注入器与定时器留给后面的测试。
	t.Cleanup(func() { _ = bs.Close() })
	// 载荷取记录上限的一半：两帧加上帧头就触发预冲刷，边界正好压在"两帧之和"上。
	const pushes = 4
	payload := make([]byte, protocol.MaxWriteRecordPlaintext/2)
	for range pushes {
		if err := bs.PushData(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := bs.Flush(); err != nil {
		t.Fatal(err)
	}
	// 读取 out 之前必须先 Close 冻结写入端：否则 cover 注入器会把新记录写回同一个无锁 buffer，
	// 与读取端之间没有 happens-before，-race 会报 DATA RACE。
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}

	rr := newTestReader(t, sk, &out)
	records := 0
	dataBytes := 0
	for {
		plaintext, err := rr.ReadRecord()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		// 断言的是写入侧上限：protocol.MaxReadRecordPlaintext 只是解码侧的天花板，用它断言等于没断言。
		if len(plaintext) > protocol.MaxWriteRecordPlaintext {
			t.Fatalf("record plaintext size %d exceeds max %d", len(plaintext), protocol.MaxWriteRecordPlaintext)
		}
		// 只统计 DATA 载荷：PADDING/COVER 会混进记录明文，按总长度比较会掩盖丢帧。
		for len(plaintext) > 0 {
			f, n, err := protocol.DecodeFrame(plaintext)
			if err != nil {
				t.Fatalf("DecodeFrame: %v", err)
			}
			if f.Type == protocol.FrameDATA {
				dataBytes += len(f.Payload)
			}
			plaintext = plaintext[n:]
		}
		records++
	}
	if want := pushes * len(payload); dataBytes != want {
		t.Fatalf("记录里的 DATA 字节 = %d，want %d（预冲刷丢帧了）", dataBytes, want)
	}
	if records == 0 {
		t.Fatal("没有写出任何记录")
	}
}

// 增长不得静默跳过：跳过会让 AppendFrame 自行 realloc 而绕过池。
func TestBatchShaperGrowFromNilBuffer(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("batch-grow-nil")
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
	impl.plaintext = nil
	impl.mu.Unlock()

	// 上界取写入上限 protocol.MaxWriteRecordPlaintext，解码侧上限与写入侧的增长边界无关。
	if err := bs.PushData(make([]byte, 1024)); err != nil {
		t.Fatalf("PushData 在 nil 缓冲区上失败: %v", err)
	}
	impl.mu.Lock()
	got := cap(impl.plaintext)
	impl.mu.Unlock()
	if got < 1024+protocol.FrameHeaderSize || got > protocol.MaxWriteRecordPlaintext {
		t.Fatalf("nil 缓冲区增长后 cap = %d，超出预期区间", got)
	}
}

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

// 断言的是 protocol.MaxReadRecordPlaintext（65,536）而不是更小的 MaxWriteRecordPlaintext：
// 明文缓冲的请求量是"帧 + 帧头"，记录上限取整后正好落到 64KB 档位。
// 观察点必须落在没有触发冲刷的帧上：冲刷会把缓冲区换出并归还池，测到的是最小缓冲。
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

	// 单帧 8KB 超过初始 4KB，但不到冲刷阈值，增长后的缓冲区会留在流里。
	const frame = 8 * 1024
	if frame+protocol.FrameHeaderSize >= impl.flushThreshold {
		t.Fatalf("测试自身选错了载荷：%d 字节的帧会直接触发冲刷", frame)
	}
	if err := bs.PushData(make([]byte, frame)); err != nil {
		t.Fatalf("PushData: %v", err)
	}
	impl.mu.Lock()
	grown := cap(impl.plaintext)
	impl.mu.Unlock()
	if grown < frame+protocol.FrameHeaderSize {
		t.Fatalf("推入 %d 字节后 cap = %d，不足以容纳该帧", frame, grown)
	}
	if grown > protocol.MaxReadRecordPlaintext {
		t.Fatalf("cap = %d 超过 64KB 档位 %d", grown, protocol.MaxReadRecordPlaintext)
	}

	// 推到尺寸边界：无论走预冲刷还是阈值冲刷，缓冲区都不得越过 64KB 档位。
	for range 16 {
		if err := bs.PushData(make([]byte, 8*1024)); err != nil {
			t.Fatalf("PushData: %v", err)
		}
		impl.mu.Lock()
		cur := cap(impl.plaintext)
		impl.mu.Unlock()
		if cur > protocol.MaxReadRecordPlaintext {
			t.Fatalf("冲刷后 cap = %d 超过 64KB 档位 %d", cur, protocol.MaxReadRecordPlaintext)
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

// 单帧上限是记录上限而不是冲刷阈值：用阈值做尺寸校验会把最大 UDP 数据报判成错误。
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

	payload := make([]byte, protocol.MaxUDPDataSize)
	if err := bs.PushData(payload); err != nil {
		t.Fatalf("PushData(MaxUDPDataSize): %v", err)
	}

	if err := bs.PushData(make([]byte, protocol.MaxWriteRecordPlaintext+1)); err == nil {
		t.Fatal("超过 MaxWriteRecordPlaintext 的帧应被拒绝")
	}
}

// netbuf 把 TCPStreamBufferSize(15,360) 与 ServerTCPStreamBufferSize(31,744) 向上取到 2 的幂，
// copyLocalToRemote 与 copyFromTarget 会原样 PushData 这个长度。
// 记录上限一旦小于它们（例如跟着 UDP 一起缩到 16,365），第一次读满就会被单帧校验打断。
func TestBatchShaperAcceptsNetbufReadFrames(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("batch-netbuf-frames")
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

	pushed := 0
	for _, max := range []int{sharedconfig.TCPStreamBufferSize, sharedconfig.ServerTCPStreamBufferSize} {
		r := netbuf.NewReader(protocol.MinRecordBufferSize, max)
		for range 4 {
			r.Grow()
		}
		buf := r.Buf()
		if err := bs.PushData(buf); err != nil {
			t.Fatalf("PushData(%d)（netbuf max=%d）: %v", len(buf), max, err)
		}
		pushed += len(buf)
		r.Release()
	}
	// 先冻结写入端再读，理由见 TestBatchShaperFlushesBeforePlainRecordLimit。
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}

	rr := newTestReader(t, sk, &out)
	dataBytes := 0
	for {
		record, err := rr.ReadRecord()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for len(record) > 0 {
			f, n, err := protocol.DecodeFrame(record)
			if err != nil {
				t.Fatalf("DecodeFrame: %v", err)
			}
			if f.Type == protocol.FrameDATA {
				dataBytes += len(f.Payload)
			}
			record = record[n:]
		}
	}
	if dataBytes != pushed {
		t.Fatalf("解出的 DATA 字节 = %d，推入 %d（读缓冲满档的帧丢了数据）", dataBytes, pushed)
	}
}

// 三条都要成立：最大数据报帧放得进一条记录；它的满记录正好落在 16KB 档位内；
// recordCeiling 与加密侧写入上限同值，否则整形器能攒出 WriteRecord 拒绝的明文，打断正常的流。
func TestBatchShaperMaxDatagramStaysInPoolClass(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("batch-ceiling-test-key")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := easycrypto.NewStreamKeys(masterKey, []byte("1234567890123456"), "/v3/udp")
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	bs := New(newTestWriter(t, sk, &out), Config{BatchWindowMS: 1000})
	t.Cleanup(func() { _ = bs.Close() })
	impl := bs.(*batchShaper)

	if maxFrame := protocol.MaxUDPDataSize + protocol.FrameHeaderSize; maxFrame > impl.recordCeiling {
		t.Fatalf("最大单帧 %d 超过记录上限 %d，会被误判为超限", maxFrame, impl.recordCeiling)
	}
	if got := protocol.MaxUDPDataSize + protocol.FrameHeaderSize + protocol.MaxCipherLenSize + protocol.MaxTagOverhead; got != protocol.UDPPoolClassSize {
		t.Fatalf("最大数据报的满记录线上长度 %d，不等于 16KB 档位 %d", got, protocol.UDPPoolClassSize)
	}
	if impl.recordCeiling != protocol.MaxWriteRecordPlaintext {
		t.Fatalf("记录上限 %d 与加密侧的写入上限 %d 不一致",
			impl.recordCeiling, protocol.MaxWriteRecordPlaintext)
	}

	if err := bs.PushData(make([]byte, protocol.MaxUDPDataSize)); err != nil {
		t.Fatalf("PushData(MaxUDPDataSize): %v", err)
	}
	// 先冻结写入端再读，理由见 TestBatchShaperFlushesBeforePlainRecordLimit。
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}

	rr := newTestReader(t, sk, &out)
	for {
		plaintext, err := rr.ReadRecord()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(plaintext) > impl.recordCeiling {
			t.Fatalf("记录明文 %d 超过上限 %d（整块记录会落到 128KB 档）",
				len(plaintext), impl.recordCeiling)
		}
	}
}

// 一条记录是一笔写入（长度前缀与密文共用同一块池缓冲），lens[i] 就是第 i 条记录的线上长度。
type recordProbe struct {
	bytes.Buffer
	lens []int
	caps []int
}

func (p *recordProbe) Write(b []byte) (int, error) {
	p.lens = append(p.lens, len(b))
	p.caps = append(p.caps, cap(b))
	return p.Buffer.Write(b)
}

// 单帧校验管不到多帧累积，唯一守住记录明文上限的是 appendFrameLocked 的预冲刷边界。
// 每轮刻意推两帧、长度之和落在记录上限与线上格式上限之间，覆盖多种切分方式。
func TestBatchShaperRecordStaysUnderCeilingOnAccumulation(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("batch-accumulation-key")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := easycrypto.NewStreamKeys(masterKey, []byte("1234567890123456"), "/v3/tcp")
	if err != nil {
		t.Fatal(err)
	}

	probe := &recordProbe{}
	bs := New(newTestWriter(t, sk, probe), Config{BatchWindowMS: 10000})
	t.Cleanup(func() { _ = bs.Close() })
	impl := bs.(*batchShaper)

	// 两帧载荷之和加帧头必须落在 (recordCeiling, MaxReadRecordPlaintext] 这条 19 字节宽的窄缝里。
	limitSum := protocol.MaxReadRecordPlaintext - 2*protocol.FrameHeaderSize

	pushed := 0
	pairs := 0
	for _, first := range []int{16, 100, 4096, 8192, 16384, 32768} {
		second := limitSum - first
		if second < 0 || second > protocol.MaxWriteRecordPlaintext-protocol.FrameHeaderSize {
			continue
		}
		sum := first + second + 2*protocol.FrameHeaderSize
		if sum <= impl.recordCeiling || sum > protocol.MaxReadRecordPlaintext {
			continue
		}
		for _, size := range []int{first, second} {
			if err := bs.PushData(make([]byte, size)); err != nil {
				t.Fatalf("PushData(%d): %v", size, err)
			}
			pushed += size
		}
		pairs++
		if err := bs.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	if pairs == 0 {
		t.Fatal("没有任何一对帧落在测试窗口内，用例退化为空转")
	}
	// 先冻结写入端再读，理由见 TestBatchShaperFlushesBeforePlainRecordLimit。
	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}

	if len(probe.lens) == 0 {
		t.Fatal("没有任何记录写出")
	}
	for i, l := range probe.lens {
		plaintext := l - protocol.MaxCipherLenSize - protocol.MaxTagOverhead
		if plaintext > impl.recordCeiling {
			t.Fatalf("第 %d 条记录明文 %d 超过上限 %d（整块记录会向上跳档）",
				i, plaintext, impl.recordCeiling)
		}
		if probe.caps[i] > protocol.MaxReadRecordPlaintext {
			t.Fatalf("第 %d 条记录引用 cap = %d 的池缓冲，超过 64KB 档位 %d",
				i, probe.caps[i], protocol.MaxReadRecordPlaintext)
		}
	}

	// 预冲刷只切记录边界：DATA 载荷之和必须等于推入总量（填充帧不属于 DATA）。
	rr := newTestReader(t, sk, &probe.Buffer)
	dataBytes := 0
	for {
		record, err := rr.ReadRecord()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for len(record) > 0 {
			frame, n, err := protocol.DecodeFrame(record)
			if err != nil {
				t.Fatalf("解码记录内的帧: %v", err)
			}
			if frame.Type == protocol.FrameDATA {
				dataBytes += len(frame.Payload)
			}
			record = record[n:]
		}
	}
	if dataBytes != pushed {
		t.Fatalf("解出的 DATA 字节 = %d，推入 %d（预冲刷丢了数据）", dataBytes, pushed)
	}
}

// cover 尺寸必须钳到线缆格式上限，否则会写出截断的 uint16 长度，或让 bytespool.Get 返回 nil。
func TestCoverNormalizeClampsFrameSize(t *testing.T) {
	cfg := Config{
		BudgetRatio: 0.10,
		MinSize:     200_000, // > 65535 且 > bytespool 上限
		MaxSize:     1_000_000,
		BudgetCap:   2_000_000,
	}.Normalize()

	maxFramePayload := protocol.MaxWriteRecordPlaintext - protocol.FrameHeaderSize
	if cfg.MinSize > maxFramePayload || cfg.MaxSize > maxFramePayload {
		t.Fatalf("cover size range not clamped: min=%d max=%d", cfg.MinSize, cfg.MaxSize)
	}
	if cfg.MaxSize < cfg.MinSize {
		t.Fatalf("MaxSize %d < MinSize %d after clamping", cfg.MaxSize, cfg.MinSize)
	}

	ci := newCoverInjector(cfg.Cover, func(protocol.Frame) error { return nil }, func() bool { return false })
	if ci == nil {
		t.Fatal("expected non-nil coverInjector")
	}
	defer ci.stop()

	minSize, maxSize := ci.coverFrameSizeRange()
	if minSize > maxFramePayload || maxSize > maxFramePayload {
		t.Fatalf("cover size range not clamped: min=%d max=%d", minSize, maxSize)
	}
}

func TestCoverInjectorSkipsDuringActiveStreaming(t *testing.T) {
	var injected []protocol.Frame
	var mu sync.Mutex
	closed := atomic.Bool{}

	ci := newCoverInjector(Cover{
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

	// 在锁下快照：注入回调会 append 共享切片，而跨 t.Fatalf 持锁会让锁永远不释放。
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
		cfg: Cover{MinSize: 128, MaxSize: 1500},
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
		cfg: Cover{MinSize: 256, MaxSize: 8192},
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

	ci := newCoverInjector(Cover{
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
				BudgetRatio:   0.5,
				IdleTimeout:   5,
				MinSize:       64,
				MaxSize:       512,
				BudgetCap:     1 << 20,
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
	// cover 空闲阈值拉到 10s：要的是手动注入的 COVER 帧触发冲刷，
	// 否则后台注入器抢先冲刷会让 PushData 同步阻塞，走不到"冲刷在飞时"这个窗口。
	bs := New(rw, Config{BatchWindowMS: 10000, IdleTimeout: 10000})
	bsImpl := bs.(*batchShaper)

	// 载荷压在批处理阈值下方 100 字节：手动注入的 COVER 帧（256+帧头=259）正好把记录推过阈值，
	// 让 injectCoverFrame 在写锁上阻塞。
	bigPayload := make([]byte, bsImpl.flushThreshold-protocol.FrameHeaderSize-100)
	if err := bs.PushData(bigPayload); err != nil {
		t.Fatal(err)
	}

	coverPayload := bytespool.Get(256)[:256]
	coverFrame := protocol.Frame{
		Type:    protocol.FrameCOVER,
		Length:  256,
		Payload: coverPayload,
	}

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

func newTestWriter(t *testing.T, sk *easycrypto.StreamKeys, w io.Writer) *easycrypto.RecordWriter {
	t.Helper()
	rw, err := sk.NewWriter(w, easycrypto.DirC2S, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	return rw
}

func newTestReader(t *testing.T, sk *easycrypto.StreamKeys, r io.Reader) *easycrypto.RecordReader {
	t.Helper()
	rr, err := sk.NewRecordReader(r, easycrypto.DirC2S, protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

// 除 FrameCOVER 之外，PushFrame 返回后调用方可以立刻复用载荷缓冲。
// handler/udp.go 与 proxy/stream.go 的 UDPExchange.Send 用 NewFrameWithPayload 直接包装调用方缓冲，
// 若整形器把载荷留到 flush 之后才读或当作池缓冲归还，会安静地造成跨流数据污染。
func TestPushFrameDoesNotRetainCallerPayload(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("batch-payload-ownership")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := easycrypto.NewStreamKeys(masterKey, []byte("1234567890123456"), "/v3/udp")
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	bs := New(newTestWriter(t, sk, &out), Config{BatchWindowMS: 1000})
	t.Cleanup(func() { _ = bs.Close() })

	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = 0x5A
	}
	frame := protocol.NewFrameWithPayload(protocol.FrameDATAGRAM, payload)
	if err := bs.PushFrame(frame); err != nil {
		t.Fatalf("PushFrame: %v", err)
	}

	for i := range payload {
		payload[i] = 0xA5
	}

	if err := bs.Close(); err != nil {
		t.Fatal(err)
	}

	rr := newTestReader(t, sk, &out)
	got, err := rr.ReadRecord()
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := protocol.DecodeFrame(got)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != protocol.FrameDATAGRAM {
		t.Fatalf("frame type = %d, want DATAGRAM", decoded.Type)
	}
	for i, b := range decoded.Payload {
		if b != 0x5A {
			t.Fatalf("载荷第 %d 字节 = %#x, want 0x5a：PushFrame 保留了调用方的缓冲，"+
				"调用方按契约覆写它造成了数据污染", i, b)
		}
	}
}

// 排空 writeNext 到 writeSeq 必须与置 writeClosed 同处 writeMu 临界区：定时器可能在 closing
// 置位前换出缓冲区并分配好 seq，那条记录会走进 writeRecordInOrder 的丢弃分支被静默扔掉。
// 这是一条压测而非确定性复现，本地通过不能证明旧代码正确。
func TestCloseFlushesEveryAllocatedSequence(t *testing.T) {
	const rounds = 50
	const goroutines = 4
	const pushesPerGoroutine = 40
	const payloadSize = 64

	masterKey, err := easycrypto.DeriveMasterKey("close-drains-allocated-seqs")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := easycrypto.NewStreamKeys(masterKey, []byte("1234567890123456"), "/v3/tcp")
	if err != nil {
		t.Fatal(err)
	}

	totalPushes := goroutines * pushesPerGoroutine

	for round := range rounds {
		t.Run(fmt.Sprintf("round_%d", round), func(t *testing.T) {
			out := &lockedBuffer{}
			bs := New(newTestWriter(t, sk, out), Config{
				// 1ms 窗口让定时器冲刷与 Close 频繁交错，正是缺陷的触发条件。
				BatchWindowMS: 1,
				BudgetRatio:   0.5,
				IdleTimeout:   5,
				MinSize:       64,
				MaxSize:       512,
				BudgetCap:     1 << 20,
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
						// 并发 flush 让多条记录同时竞争 writeMu，放大与 Close 交错的窗口。
						if i%8 == 0 {
							if err := bs.Flush(); err != nil {
								t.Errorf("Flush failed (goroutine %d): %v", gid, err)
								return
							}
						}
					}
				}(g)
			}
			wg.Wait()

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
						t.Fatalf("decode frame failed in record %d", recordCount-1)
					}
					remaining = remaining[n:]
					if frame.Type == protocol.FrameDATA && len(frame.Payload) >= 4 {
						seenSeqs[binary.BigEndian.Uint32(frame.Payload[:4])] = true
					}
				}
			}

			if recordCount == 0 {
				t.Fatalf("no records decrypted in round %d: Close dropped an allocated sequence", round)
			}
			for i := range totalPushes {
				if !seenSeqs[uint32(i)] {
					t.Fatalf("sequence %d missing in round %d: a record was dropped before writeClosed", i, round)
				}
			}
		})
	}
}
