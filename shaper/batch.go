package shaper

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/bytespool"
)

type batchShaper struct {
	writer    *crypto.RecordWriter
	plaintext []byte
	timer     *time.Timer
	mu        sync.Mutex
	writeMu   sync.Mutex // 跨 goroutine 串行化 WriteRecord 调用
	// maxChunkSize 同时充当两个边界，这是由约束链决定的，不是可以分别调整的两个值：
	//
	//   a) 单帧合法性：UDP 数据报帧最大 protocol.MaxUDPDataSize(65507)，
	//      因此单帧上限必须 ≥ 该值 + 帧头；
	//   b) 缓冲档位：明文缓冲按 2 的幂从池里取，上限必须 ≤ 池的 64KB 档，
	//      否则一块最大记录的明文缓冲会落到 128KB 档。
	//
	// 两者共同把它钉在 protocol.MaxPlainRecordSize：它 ≥ 65510（容纳最大单帧），
	// 又正好是池的 64KB 档位。记录本身还能更大（线上格式的 3 字节长度前缀可
	// 表达 16MB），但那个更大的尺寸只用于解码既有记录，见 crypto.MaxCipherRecordSize。
	maxChunkSize int
	// recordCeiling 是一条记录的明文的实际上限，由"密文缓冲必须落在池的
	// 64KB 档位内"唯一确定：一条记录占用的池缓冲是 MaxCipherLenSize + 明文 +
	// AEAD 标签（长度前缀与密文取样于同一块 2 的幂缓冲），因此
	//
	//	明文 ≤ 65536 - 3 - 16 = 65517
	//
	// 明文一旦超过它，密文缓冲就从 64KB 档跳到 128KB 档——为十几字节的溢出
	// 付一倍的池保留与瞬时分配（最大 UDP 数据报 65,507 + 帧头 3 = 65,510，
	// 正好落在 65,517 之内，因此这个上限不会误伤最大的合法单帧）。
	//
	// 它只用于**记录尺寸目标**（填充预算与"明文不得超过"的约束）：校验单帧
	// 合法性仍然按 maxChunkSize，否则 65,510 字节的帧会被误判为超限。
	// protocol.MaxPlainRecordSize 常量本身不动——填充档位与批处理节奏由它决定，
	// 缩小它才是上一个 commit 明确拒绝的那件事。
	recordCeiling int
	// flushThreshold 是批处理的目标：攒到它的 9/10 就冲刷，让记录尺寸落在
	// 填充的目标档位附近，而不是每次都顶到上限。
	flushThreshold int
	window         time.Duration
	timerStarted   bool
	closing        atomic.Bool
	writeClosed    atomic.Bool // 在 Close 的 flush 之后置位；防止 handler 返回后继续写入
	err            error
	cover          *coverInjector
}

// New 在给定的 record writer 之上构建一个流量整形器。cfg 在此处规范化
// （参见 Config.Normalize），因此调用方可以直接传入原始的配置文件值。
//
// 明文缓冲区按需增长：流的生命周期从 minRecordBufferSize 起步，只有真正
// 攒够数据（或出现超大单帧）时才长到 protocol.MaxPlainRecordSize。空闲流、
// 心跳流与短命流因此只占最少的内存，而不是每条流无条件预留一整块记录缓冲区。
func New(writer *crypto.RecordWriter, cfg Config) Shaper {
	cfg = cfg.Normalize()

	bs := &batchShaper{
		writer: writer,
		// 缓冲从初始大小起步，按需增长（见 ensureCapacity）。
		plaintext: bytespool.Get(minRecordBufferSize)[:0],
		// maxChunkSize 取线上格式上限，理由见字段上的约束链说明：
		// 它既要容纳最大的合法单帧（UDP 数据报 65507B + 帧头），又要正好是
		// 池的 64KB 档位。
		maxChunkSize: protocol.MaxPlainRecordSize,
		// recordCeiling 是明文上限，由"密文缓冲落在池的 64KB 档位"确定，
		// 见字段说明。
		recordCeiling: protocol.MaxPlainRecordSize - protocol.MaxCipherLenSize - protocol.MaxTagOverhead,
		// flushThreshold 是批处理的目标：攒到上限的 9/10 就冲刷。
		flushThreshold: protocol.MaxPlainRecordSize * 9 / 10,
		window:         time.Duration(cfg.BatchWindowMS) * time.Millisecond,
	}
	bs.timer = time.AfterFunc(bs.window, bs.onTimer)
	bs.timer.Stop()

	bs.cover = newCoverInjector(cfg.Cover, bs.injectCoverFrame, bs.isClosing)
	return bs
}

// minRecordBufferSize 是每条流的明文缓冲区初始大小。它是"流"这个维度的内存
// 下限：常驻连接、心跳流、探测流在数量上往往占绝大多数，把它们从一整块记录
// 缓冲区（64KB）降到这么小是这次收敛里收益最大的一项。缓冲按需增长到
// protocol.MaxPlainRecordSize，见 protocol.MinRecordBufferSize 的说明。
const minRecordBufferSize = protocol.MinRecordBufferSize

// ensureCapacity 确保明文缓冲区至少能容纳 size 字节，必要时按需增长。
// 调用方必须持有 bs.mu，且必须保证 size ≤ protocol.MaxPlainRecordSize
// （两条调用路径都由 appendFrameLocked 的帧级检查或下面的填充预算保证）。
func (bs *batchShaper) ensureCapacity(size int) {
	if cap(bs.plaintext) >= size {
		return
	}
	bs.growLocked(size)
}

// growLocked 把明文缓冲区换到一块更大的池化缓冲区，并归还旧的那块。
// 增长按 2 倍摊销，但至少满足本次请求，上限是线上格式的 protocol.MaxPlainRecordSize。
//
// 这里不检查 bytespool.Get 的返回值：newCap 由上面的裁剪保证落在
// [minRecordBufferSize, protocol.MaxPlainRecordSize] 之内，是池内合法的 2 的幂
// 档位，Get 必定返回可用的缓冲区。而且这个函数**必须**真的把缓冲区换大——
// 静默跳过会让紧随其后的 protocol.AppendFrame 因容量不足自行 realloc，
// 从而绕过池，正是这次改动要杜绝的路径。
//
// 调用方必须持有 bs.mu。
func (bs *batchShaper) growLocked(size int) {
	newCap := min(max(cap(bs.plaintext)*2, size, minRecordBufferSize), protocol.MaxPlainRecordSize)

	buf := bytespool.Get(newCap)
	// 明文的前 len 字节必须搬过去：appendFrame 只在 Get 返回的切片上追加。
	n := copy(buf, bs.plaintext)
	// 旧缓冲区在搬移之后、覆盖字段之前归还（它已经无人引用）。
	// 缓冲区为 nil 时（尚未分配）跳过：nil 的 cap 是 0。
	if old := bs.plaintext; cap(old) > 0 {
		bytespool.MustPut(old[:cap(old)])
	}
	bs.plaintext = buf[:n]
}

// appendFrameLocked 将指定类型的帧追加到明文缓冲区：当记录即将溢出时先冲刷，
// 缓冲不足时按需增长，最后把帧编码进去（载荷始终被复制进 bs.plaintext）。
// putPayload 标记来自 bytespool 的 payload，追加完成后必须归还。
// 调用方必须持有 bs.mu。
//
// putPayload 只对 FrameCOVER 为真，这是**载荷所有权契约的另一半**：其余帧类型
// （DATA/DATAGRAM/FIN/RST/PADDING）的载荷一律不归还、不保留，因此调用方可以在
// PushFrame 返回后立刻复用它。服务端 UDP 数据报路径（handler/udp.go 的
// NewFrameWithPayload）与客户端 UDP 上行（proxy/stream.go 的 UDPExchange.Send）
// 都依赖这一点来避免每数据报一次多余复制：若改成"归还任何 cap 是 2 的幂的
// 载荷"，这两处会变成把仍在使用的缓冲归还池，造成跨流数据污染。
func (bs *batchShaper) appendFrameLocked(ftype protocol.FrameType, payload []byte, putPayload bool) error {
	frameSize := protocol.FrameHeaderSize + len(payload)
	if frameSize > bs.maxChunkSize {
		if putPayload {
			bs.putPooledPayload(payload)
		}
		return fmt.Errorf("shaper: frame size %d exceeds max record size %d", frameSize, bs.maxChunkSize)
	}

	// 若追加会导致记录溢出，则预先冲刷。这一步必须在容量检查之前：冲刷会
	// 换出一块空的缓冲区，原来"放不下"的帧因此往往又能放下了（例如缓冲区
	// 已攒到上限，再来一帧只能放进下一条记录）。
	// 边界取 maxChunkSize 而不是 flushThreshold：单个超过阈值的大帧
	//（UDP 数据报）也是合法帧，必须能放进一条记录。
	if len(bs.plaintext) > 0 && len(bs.plaintext)+frameSize > bs.maxChunkSize {
		if err := bs.flushAndWrite(false); err != nil {
			// 该帧从未被追加，因此在此归还池化 payload：没有其他人会归还它。
			if putPayload {
				bs.putPooledPayload(payload)
			}
			return err
		}
	}

	// 缓冲不足时按需增长。必须在 AppendFrame 之前做：否则 protocol.AppendFrame
	// 会在容量不足时自行 realloc，绕过池化缓冲区，使这块内存既不受池的保留
	// 上限约束，也无法在 Close 时归还。
	bs.ensureCapacity(len(bs.plaintext) + frameSize)

	bs.plaintext = protocol.AppendFrame(bs.plaintext, protocol.Frame{Type: ftype, Payload: payload})

	if putPayload {
		bs.putPooledPayload(payload)
	}

	// 达到阈值后冲刷。
	if len(bs.plaintext) >= bs.flushThreshold {
		return bs.flushAndWrite(false)
	}

	bs.timerStarted = true
	bs.timer.Reset(bs.window)
	return nil
}

// PushData 将原始数据作为 DATA 帧添加。返回时不持有锁。
func (bs *batchShaper) PushData(data []byte) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closing.Load() {
		return nil
	}
	if bs.err != nil {
		return bs.err
	}

	if bs.cover != nil {
		bs.cover.addBudget(protocol.FrameHeaderSize + len(data))
	}
	return bs.appendFrameLocked(protocol.FrameDATA, data, false)
}

// PushFrame 添加一个预先构建好的帧（FIN、RST、COVER 等）。返回时不持有锁。
func (bs *batchShaper) PushFrame(f protocol.Frame) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closing.Load() {
		return nil
	}
	if bs.err != nil {
		return bs.err
	}

	// 让 Length 与 payload 保持一致：下面的记录大小检查和整形器的 cover 预算
	// 都使用 EncodedLen（3 + Length），因此 Length 与 payload 不一致的帧
	// 会让超大帧绕过这些检查。线缆上的头部由 protocol.AppendFrame 根据
	// len(Payload) 推导。
	if len(f.Payload) > math.MaxUint16 {
		return fmt.Errorf("shaper: frame payload too large: %d", len(f.Payload))
	}
	f.Length = uint16(len(f.Payload))

	if bs.cover != nil && f.Type != protocol.FrameCOVER && f.Type != protocol.FramePADDING {
		bs.cover.addBudget(f.EncodedLen())
	}
	return bs.appendFrameLocked(f.Type, f.Payload, f.Type == protocol.FrameCOVER)
}

// putPooledPayload 在 cover payload 确实是池缓冲区（容量为池上限内的
// 2 的幂）时将其归还 bytespool。调用方提供的堆切片会使 MustPut
// 因 2 的幂不变式而 panic，因此这类 payload 留给 GC 回收。
func (bs *batchShaper) putPooledPayload(payload []byte) {
	if len(payload) > 0 && cap(payload) <= bytespool.MaxSize && cap(payload)&(cap(payload)-1) == 0 {
		bytespool.MustPut(payload)
	}
}

// Flush 触发立即冲刷。不要求调用方持有锁。
func (bs *batchShaper) Flush() error {
	return bs.flush(true)
}

// Close 停止 cover 流量，冲刷剩余数据，并将缓冲区归还池。
func (bs *batchShaper) Close() error {
	bs.mu.Lock()
	bs.closing.Store(true)
	if bs.cover != nil {
		bs.cover.stop()
	}
	bs.timerStarted = false
	bs.timer.Stop()
	bs.mu.Unlock()

	err := bs.flush(true)

	// 与 writeMu 串行化：此后任何获取 writeMu 的 flushAndWrite 都会看到
	// writeClosed 并丢弃其数据，防止向已结束的 HTTP handler 写入。
	// 此前已获取 writeMu 的冲刷会正常完成；我们在此阻塞直到它们结束。
	bs.writeMu.Lock()
	bs.writeClosed.Store(true)
	bs.writeMu.Unlock()

	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.plaintext != nil {
		bytespool.MustPut(bs.plaintext[:cap(bs.plaintext)])
		bs.plaintext = nil
	}
	return err
}

// flushLocked 停止定时器，追加填充，并交换明文缓冲区。
// 必须在持有 mu 时调用。返回待写入的数据，缓冲区为空时返回 nil。
func (bs *batchShaper) flushLocked() []byte {
	if len(bs.plaintext) == 0 {
		return nil
	}

	bs.timerStarted = false
	bs.timer.Stop()

	// 填充同样要在池化缓冲区里完成：以记录上限为预算生成填充帧，再按结果增长
	// 缓冲区，从而避免 AppendFrame 因容量不足自行 realloc，把这块内存从池的
	// 管理里漏出去。预算取 recordCeiling（而不是缓冲容量 maxChunkSize）：填充后
	// 的记录在加过 3 字节长度前缀与 16 字节 AEAD 标签之后仍须落进 64KB 档位。
	//
	// 代价是贴着记录上限的记录会丢掉尾部填充：那些记录本来就落在填充的目标尺寸
	// 档位上，少掉的是 1~63 字节的尾部随机化，属可接受；不为它先增长一档。
	if padFrame, ok := BuildPaddingFrame(len(bs.plaintext), bs.recordCeiling); ok {
		bs.ensureCapacity(len(bs.plaintext) + protocol.FrameHeaderSize + len(padFrame.Payload))
		bs.plaintext = protocol.AppendFrame(bs.plaintext, padFrame)
	}

	// 交换缓冲区：把攒好的数据交给 I/O，这条流同时拿到一块新的明文缓冲区，
	// 因此并发的 PushData / PushFrame 不必等待这次 I/O 完成。
	//
	// 未增长过的流（多数流自始至终都在这一档）直接复用同一块缓冲区，
	// 彻底避免"每次冲刷都取一块新的"；已经增长过的流换回初始大小，
	// 让它静默后能把大缓冲区让回池里，下一轮增长时正好复用
	// （Get(4KB) 与 Put(64KB) 走不同档位，不会互相污染）。
	data := bs.plaintext
	if cap(bs.plaintext) > minRecordBufferSize {
		// 换出大缓冲区：data 由 flushAndWrite 在写完记录后归还
		//（data[:cap(data)] 的 cap 是 2 的幂，符合池的约定）。
		bs.plaintext = bytespool.Get(minRecordBufferSize)[:0]
		return data
	}

	// 小缓冲区：从池里再取一块给流，把 data 原样交给 I/O。
	// Get(4096) 必定返回可用的缓冲区（池内合法的 2 的幂档位），因此这里不需要
	// 守卫；而万一流侧拿不到新缓冲区，也绝不能让它继续指向即将被归还给池的
	// data——那会让后续 append 写进已入池的缓冲区，造成跨流数据污染。
	bs.plaintext = bytespool.Get(minRecordBufferSize)[:0]
	return data
}

// flushAndWrite 冲刷当前缓冲区并写出加密记录。
// 必须在持有 mu 时调用。I/O 期间临时释放 mu，返回前重新获取。
// 当 forceFlush 为 true 时，写入后会触发显式的 HTTP/2 flush，
// 以确保立即投递。
func (bs *batchShaper) flushAndWrite(forceFlush bool) error {
	data := bs.flushLocked()
	if data == nil {
		return nil
	}

	bs.mu.Unlock()

	bs.writeMu.Lock()
	if bs.writeClosed.Load() {
		bs.writeMu.Unlock()
		bytespool.MustPut(data[:cap(data)])
		bs.mu.Lock()
		return nil
	}
	err := bs.writer.WriteRecord(data)
	if err == nil && forceFlush {
		bs.writer.Flush()
	}
	bs.writeMu.Unlock()

	bytespool.MustPut(data[:cap(data)])

	bs.mu.Lock()
	if err != nil {
		bs.err = err
	}
	return err
}

// flush 获取锁，冲刷缓冲区，然后释放锁。
// 调用方不得持有 bs.mu。
func (bs *batchShaper) flush(forceFlush bool) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return bs.flushAndWrite(forceFlush)
}

func (bs *batchShaper) onTimer() {
	if bs.closing.Load() {
		return
	}
	bs.mu.Lock()
	bs.timerStarted = false
	bs.mu.Unlock()
	if err := bs.flush(true); err != nil {
		if isClosedStreamError(err) {
			// 对端已关闭该流（例如 handler 仍在关闭 relay 时收到
			// RST_STREAM/FIN）。失败的冲刷只是拆除路径收尾，并非真正的错误。
			log.Debug("[SHAPER] timer flush aborted, stream closed", "err", err)
			return
		}
		log.Info("[SHAPER] timer flush error", "err", err)
	}
}

// isClosedStreamError 报告 err 是否表明底层流已被对端关闭
// （HTTP/2 流重置、管道关闭、连接关闭）。这类错误在拆除阶段是无害的：
// 对端已放弃该流，失败的冲刷只是 relay 收尾。
func isClosedStreamError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	// "http2: stream closed" 是标准库中未导出的哨兵错误，因此只能通过
	// 字符串匹配。crypto 会保留错误链（"crypto: write record: ..."），
	// 所以子串匹配就足够了。
	return strings.Contains(strings.ToLower(err.Error()), "stream closed")
}

func (bs *batchShaper) injectCoverFrame(f protocol.Frame) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closing.Load() || bs.err != nil {
		// 归还池化 payload，避免整形器已关闭或已出错时泄漏缓冲区。
		if f.Type == protocol.FrameCOVER {
			bs.putPooledPayload(f.Payload)
		}
		return nil
	}

	return bs.appendFrameLocked(f.Type, f.Payload, f.Type == protocol.FrameCOVER)
}

func (bs *batchShaper) isClosing() bool {
	return bs.closing.Load()
}
