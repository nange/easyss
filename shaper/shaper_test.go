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
	// 载荷取记录上限的一半：两条加上帧头就会越过记录上限，触发预冲刷；而任何
	// 一条记录都远到不了上限（32,758+3 << 65,517），边界正好压在"两帧之和"上。
	// 取值锚在协议常量上（而不是 16KB 之类的字面量），这样上限调整时这条用例
	// 仍然守着"预冲刷边界"本身。
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
	dataBytes := 0
	for {
		plaintext, err := rr.ReadRecord()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		// 记录明文不得超过记录上限——它才是写入侧的真实边界，线上格式上限
		// (protocol.MaxReadRecordPlaintext) 只是解码侧的天花板，用它断言等于没断言。
		// 这条断言与下面的字节守恒一起，就是"预冲刷边界生效且不丢帧"的完整判据：
		// 少了预冲刷，多帧累积会把记录顶过上限；少了字节守恒，多冲刷会丢帧。
		if len(plaintext) > protocol.MaxWriteRecordPlaintext {
			t.Fatalf("record plaintext size %d exceeds max %d", len(plaintext), protocol.MaxWriteRecordPlaintext)
		}
		// 只统计 DATA 载荷：PADDING/COVER 帧会混进记录明文，按总长度比较
		// 理论上能掩盖丢帧（cover 默认开启，idle 300ms 就会注入）。
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
	// 载荷一字节不少地落在记录里：预冲刷只改变记录边界，绝不能丢帧
	// （多帧累积顶过上限时报错、或静默丢弃，都会在这里暴露）。
	if want := pushes * len(payload); dataBytes != want {
		t.Fatalf("记录里的 DATA 字节 = %d，want %d（预冲刷丢帧了）", dataBytes, want)
	}
	// 记录条数不做断言：它由预冲刷边界与批处理阈值共同决定，而不是由本用例
	// 要守的单一关系决定——锚在它上面只会让用例随阈值调整而碎。
	if records == 0 {
		t.Fatal("没有写出任何记录")
	}
}

// TestBatchShaperGrowFromNilBuffer 固定 growLocked 对未分配缓冲区的行为：
// 流侧缓冲区为 nil（cap 0）时必须照常增长并搬运，且不因归还未分配的缓冲区
// 而 panic。它同时是"增长不得静默跳过"的回归：静默跳过会让 AppendFrame
// 自行 realloc，绕过池。
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

	// 从 nil 起步推入数据：必须成功且缓冲区落到合法档位。上界取写入上限
	// (protocol.MaxWriteRecordPlaintext) 而不是解码侧上限
	// (protocol.MaxReadRecordPlaintext)：后者与写入侧的增长边界无关。
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
// 且任何时刻都不会超过**记录上限所在的 64KB 档位**——后者是每个流的常驻上限，
// 也是这套按需增长存在的全部理由。
//
// 注意这里断言的是 protocol.MaxReadRecordPlaintext（65,536）而不是更小的
// protocol.MaxWriteRecordPlaintext（65,517）：明文缓冲的请求量是"帧 + 帧头"，记录
// 上限本身取整后正好落到该档位，跨过它才是回归。
//
// 观察点必须落在"没有触发冲刷"的帧上：冲刷一旦发生，缓冲区就被换出并归还池，
// 手上的 cap 会是换回来的那块最小缓冲，测到的是冲刷后的状态而不是增长后的状态。
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

	// 单帧 8KB：超过初始 4KB 必须增长，但不到冲刷阈值（记录上限的 9/10），
	// 因此增长后的缓冲区会留在流里，可以被观察到。
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

	// 再把缓冲区推到尺寸边界：持续推入，让多帧累积撞上预冲刷边界；无论走
	// 预冲刷还是阈值冲刷，缓冲区都不得越过 64KB 档位（记录上限 + 19 正好是
	// 该档位，取整后不会更大）。
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

// TestBatchShaperAcceptsLargeDatagramFrame 固定单帧上限是记录上限：
// UDP 数据报帧最大可达 protocol.MaxUDPDataSize，它必然超过批处理的冲刷阈值，
// 但必须被当作合法帧接受（历史缺陷：用阈值去做尺寸校验会把它判成错误）。
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

	// 最大合法数据报：它与记录上限只差一个帧头，因此必然超过批处理的冲刷阈值，
	// 但必须被当作合法帧接受（历史缺陷：用阈值去做尺寸校验会把它判成错误）。
	payload := make([]byte, protocol.MaxUDPDataSize)
	if err := bs.PushData(payload); err != nil {
		t.Fatalf("PushData(MaxUDPDataSize): %v", err)
	}

	// 单帧超过记录上限时仍必须被拒绝（线上格式的 3 字节长度前缀虽能表达更大值，
	// 但写入侧的上限是 protocol.MaxWriteRecordPlaintext）。
	if err := bs.PushData(make([]byte, protocol.MaxWriteRecordPlaintext+1)); err == nil {
		t.Fatal("超过 MaxWriteRecordPlaintext 的帧应被拒绝")
	}
}

// TestBatchShaperAcceptsNetbufReadFrames 固定 TCP 读缓冲的满档必须能作为单帧
// 通过：netbuf 把 config.TCPStreamBufferSize(15,360) 与
// ServerTCPStreamBufferSize(31,744) 向上取到 2 的幂（16,384 / 32,768），
// copyLocalToRemote 与 copyFromTarget 会原样 PushData 这个长度的切片。
//
// 记录上限一旦小于它们（例如跟着 UDP 一起缩到 16,365），大流量 TCP 流会在
// 第一次读满时被单帧校验打断——这是本用例要守住的回归。
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

// TestBatchShaperMaxDatagramStaysInPoolClass 固定数据报链路的三个方向：
//
//   - 最大的数据报帧必须放得进一条记录，不能被单帧校验判成超限；
//   - 它的满记录（帧 + 长度前缀 + 16 字节标签）必须正好落在 16KB 档位内，
//     多一字节就会向上跳一档；
//   - recordCeiling 必须与加密侧的写入上限是同一个值，否则整形器能攒出
//     WriteRecord 拒绝的明文，把一条正常的流打断。
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

	// 推入一个最大数据报：必须被接受，而不是报"超过最大记录尺寸"。
	if err := bs.PushData(make([]byte, protocol.MaxUDPDataSize)); err != nil {
		t.Fatalf("PushData(MaxUDPDataSize): %v", err)
	}
	// 先冻结写入端再读，理由见 TestBatchShaperFlushesBeforePlainRecordLimit
	// 对 cover 注入器与批处理定时器的说明。
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

// recordProbe 记录每一笔落到 io.Writer 上的写入的长度与容量，并把字节透传给
// 内嵌的 buffer 供随后解码。一条记录现在是一笔写入（长度前缀与密文共用同一块
// 池缓冲），因此 lens[i] 就是第 i 条记录的线上长度。
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

// TestBatchShaperRecordStaysUnderCeilingOnAccumulation 固定"**多帧累积**也不能越过
// 记录明文上限"：单帧校验管不到累积，唯一能守住它的地方是 appendFrameLocked 的
// 预冲刷边界。历史缺陷：边界取的是线上格式上限，于是"多帧之和落在记录上限与该
// 上限之间"的记录会带着更大档位的缓冲被加密出去——而
// TestBatchShaperMaxDatagramStaysInPoolClass 只压单帧，走不到那条路径。
//
// 因此每一轮刻意推两帧、长度之和固定落在记录上限与线上格式上限之间，并覆盖从
// "小帧在前"到"TCP 读缓冲满档在前"的不同切分方式。
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

	// 两帧载荷之和的**目标**取"整块记录正好占满 64KB 档位"再扣掉两个帧头，
	// 真正的判据是实际组合：两帧的载荷之和加帧头必须落在
	// (recordCeiling, MaxReadRecordPlaintext] 这条窄缝里。窗口宽度只有
	// MaxCipherLenSize+MaxTagOverhead（19 字节），逐组合校验。
	limitSum := protocol.MaxReadRecordPlaintext - 2*protocol.FrameHeaderSize

	pushed := 0
	pairs := 0
	for _, first := range []int{16, 100, 4096, 8192, 16384, 32768} {
		second := limitSum - first
		// 第二帧也必须是一条合法单帧（放得进一条记录），否则整对跳过。
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
	// 窗口本身必须真的被覆盖到：全部组合被跳过等于这条用例什么也没测。
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

	// 预冲刷只应把记录切开，不能丢字节：把每条记录解回帧，DATA 载荷之和必须等于
	// 推入的总量（填充帧只增加长度，不属于 DATA）。
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

	maxFramePayload := protocol.MaxWriteRecordPlaintext - protocol.FrameHeaderSize
	if cfg.Cover.MinSize > maxFramePayload || cfg.Cover.MaxSize > maxFramePayload {
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
	if minSize > maxFramePayload || maxSize > maxFramePayload {
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
	// cover 的空闲阈值拉长到 10s：本用例要的是**手动注入**的 COVER 帧触发冲刷，
	// 而不是后台注入器在 PushData 之前或期间抢先冲刷——那会让 PushData 同步阻塞，
	// 测试根本走不到"冲刷在飞时"这个窗口。
	bs := New(rw, Config{BatchWindowMS: 10000, Cover: CoverConfig{IdleTimeout: 10000}})
	bsImpl := bs.(*batchShaper)

	// 载荷压在批处理阈值下方 100 字节：PushData 自身不冲刷，随后手动注入的
	// COVER 帧（256 字节 + 帧头 = 259，大于 100 字节的余量）正好把记录推过阈值，
	// 让 injectCoverFrame 在写锁上阻塞——这正是本用例要覆盖的窗口。
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

// TestPushFrameDoesNotRetainCallerPayload 固定**载荷所有权契约的另一半**：
// 除 FrameCOVER 之外，PushFrame 返回后调用方可以立刻复用载荷缓冲。
//
// 服务端 UDP 下行（handler/udp.go）与客户端 UDP 上行（proxy/stream.go 的
// UDPExchange.Send）都依赖它来避免每个数据报一次多余复制：它们用
// protocol.NewFrameWithPayload 直接包装调用方的缓冲，而不是先复制一份。
// 如果哪天 shaper 改成"归还任何池化载荷"或把载荷留到 flush 之后才读，
// 那两处会安静地把仍在使用的缓冲归还池——跨流数据污染，且不会有任何报错。
//
// 这里用"PushFrame 返回后立刻覆写载荷"来暴露这种保留：若载荷被延后读取，
// 解密出的记录里就会是覆写后的字节，而不是原始内容。
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

	// 载荷来自池外的堆切片（模拟 handler 从读缓冲拷出的数据报）：整形器
	// 绝不能把它当作可归还的池缓冲。
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = 0x5A
	}
	frame := protocol.NewFrameWithPayload(protocol.FrameDATAGRAM, payload)
	if err := bs.PushFrame(frame); err != nil {
		t.Fatalf("PushFrame: %v", err)
	}

	// 返回即复用：覆写整块载荷。
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
	// 同一记录里还会跟着 flush 追加的 PADDING 帧，因此只校验数据报载荷本身。
	for i, b := range decoded.Payload {
		if b != 0x5A {
			t.Fatalf("载荷第 %d 字节 = %#x, want 0x5a：PushFrame 保留了调用方的缓冲，"+
				"调用方按契约覆写它造成了数据污染", i, b)
		}
	}
}
