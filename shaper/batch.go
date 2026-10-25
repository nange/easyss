package shaper

import (
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
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

// ErrClosed 表示 Shaper 已开始关闭流程，帧没有被接受。
var ErrClosed = errors.New("shaper: closed")

type batchShaper struct {
	writer    *crypto.RecordWriter
	plaintext []byte
	timer     *time.Timer
	mu        sync.Mutex
	writeMu   sync.Mutex

	// 记录必须按换出顺序写出：释放 bs.mu 之后才做 I/O，后换出的可能先拿到
	// writeMu，把 DATA 段静默重排。
	writeCond *sync.Cond
	writeSeq  uint64
	writeNext uint64
	// recordCeiling 是一条记录的明文上限，与 crypto.RecordWriter 的写入上限是
	// 同一个常量：攒出更长的明文会让 WriteRecord 报错并打断这条流。
	recordCeiling  int
	flushThreshold int
	window         time.Duration
	timerStarted   bool
	closing        atomic.Bool
	writeClosed    atomic.Bool // 在 Close 的 flush 之后置位，防止 handler 返回后继续写入
	err            error
	cover          *coverInjector
	// paddingRNG 归本实例所有，在 bs.mu 下使用，避免所有流共用一把全局锁。
	paddingRNG *rand.ChaCha8
}

func New(writer *crypto.RecordWriter, cfg Config) Shaper {
	cfg = cfg.Normalize()

	bs := &batchShaper{
		writer:         writer,
		plaintext:      bytespool.Get(minRecordBufferSize)[:0],
		recordCeiling:  protocol.MaxWriteRecordPlaintext,
		flushThreshold: protocol.MaxWriteRecordPlaintext * 9 / 10,
		window:         time.Duration(cfg.BatchWindowMS) * time.Millisecond,
		paddingRNG:     newSeededChaCha8(),
	}
	bs.writeCond = sync.NewCond(&bs.writeMu)
	bs.timer = time.AfterFunc(bs.window, bs.onTimer)
	bs.timer.Stop()

	bs.cover = newCoverInjector(cfg.Cover, bs.injectCoverFrame, bs.isClosing)
	return bs
}

const minRecordBufferSize = protocol.MinRecordBufferSize

// 调用方必须持有 bs.mu。
func (bs *batchShaper) ensureCapacity(size int) {
	if cap(bs.plaintext) >= size {
		return
	}
	bs.growLocked(size)
}

// growLocked 换到更大的池化缓冲区，调用方必须持有 bs.mu。必须真的换大：容量
// 不足时 protocol.AppendFrame 会自行 realloc，绕过缓冲池。
func (bs *batchShaper) growLocked(size int) {
	newCap := min(max(cap(bs.plaintext)*2, size, minRecordBufferSize), protocol.MaxReadRecordPlaintext)

	buf := bytespool.Get(newCap)
	n := copy(buf, bs.plaintext)
	if old := bs.plaintext; cap(old) > 0 {
		bytespool.MustPut(old[:cap(old)])
	}
	bs.plaintext = buf[:n]
}

// appendFrameLocked 追加一帧。putPayload 只对 FrameCOVER 为真：其余帧的载荷不
// 归还、不保留，调用方返回后即可复用；按 cap 判断会把仍在用的缓冲归还池。
func (bs *batchShaper) appendFrameLocked(ftype protocol.FrameType, payload []byte, putPayload bool) error {
	frameSize := protocol.FrameHeaderSize + len(payload)
	if frameSize > bs.recordCeiling {
		if putPayload {
			bs.putPooledPayload(payload)
		}
		return fmt.Errorf("shaper: frame size %d exceeds max record size %d", frameSize, bs.recordCeiling)
	}

	// 预冲刷必须排在容量检查之前：冲刷换出空缓冲，原本"放不下"的帧往往又能
	// 放下。边界取 recordCeiling 而非 flushThreshold，超阈值的大帧也是合法帧。
	if len(bs.plaintext) > 0 && len(bs.plaintext)+frameSize > bs.recordCeiling {
		if err := bs.flushAndWrite(false); err != nil {
			// 帧未被追加，池化 payload 由此处唯一归还。
			if putPayload {
				bs.putPooledPayload(payload)
			}
			return err
		}
	}

	bs.ensureCapacity(len(bs.plaintext) + frameSize)

	bs.plaintext = protocol.AppendFrame(bs.plaintext, protocol.Frame{Type: ftype, Payload: payload})

	if putPayload {
		bs.putPooledPayload(payload)
	}

	if len(bs.plaintext) >= bs.flushThreshold {
		return bs.flushAndWrite(false)
	}

	bs.timerStarted = true
	bs.timer.Reset(bs.window)
	return nil
}

func (bs *batchShaper) PushData(data []byte) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closing.Load() {
		return ErrClosed
	}
	if bs.err != nil {
		return bs.err
	}

	if bs.cover != nil {
		bs.cover.addBudget(protocol.FrameHeaderSize + len(data))
	}
	return bs.appendFrameLocked(protocol.FrameDATA, data, false)
}

func (bs *batchShaper) PushFrame(f protocol.Frame) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closing.Load() {
		return ErrClosed
	}
	if bs.err != nil {
		return bs.err
	}

	// Length 必须与 payload 一致：记录大小检查与 cover 预算都用 EncodedLen，不一致
	// 会让超大帧绕过检查。
	if len(f.Payload) > math.MaxUint16 {
		return fmt.Errorf("shaper: frame payload too large: %d", len(f.Payload))
	}
	f.Length = uint16(len(f.Payload))

	if bs.cover != nil && f.Type != protocol.FrameCOVER && f.Type != protocol.FramePADDING {
		bs.cover.addBudget(f.EncodedLen())
	}
	return bs.appendFrameLocked(f.Type, f.Payload, f.Type == protocol.FrameCOVER)
}

// putPooledPayload 只归还池内 2 的幂档位缓冲；堆切片交给 GC，MustPut 会 panic。
func (bs *batchShaper) putPooledPayload(payload []byte) {
	if len(payload) > 0 && cap(payload) <= bytespool.MaxSize && cap(payload)&(cap(payload)-1) == 0 {
		bytespool.MustPut(payload)
	}
}

func (bs *batchShaper) Flush() error {
	return bs.flush(true)
}

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

	// 必须先排空已分配的序号再置 writeClosed：定时器可能早已换出缓冲、分配好
	// seq 并等在 writeCond 上，直接置位会让那条记录走丢弃分支。
	//
	// writeSeq 的写方在 bs.mu 内，这里用同一把锁取快照：closing 已置位，所有 append
	// 路径都在 bs.mu 下提前返回，快照之后不会再有携带数据的新 seq。
	bs.mu.Lock()
	pending := bs.writeSeq
	bs.mu.Unlock()

	bs.writeMu.Lock()
	for bs.writeNext < pending {
		bs.writeCond.Wait()
	}
	// 此后拿到 writeMu 的 flushAndWrite 看到 writeClosed 就丢弃，不再写已结束的 handler。
	bs.writeClosed.Store(true)
	bs.writeCond.Broadcast()
	bs.writeMu.Unlock()

	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.plaintext != nil {
		bytespool.MustPut(bs.plaintext[:cap(bs.plaintext)])
		bs.plaintext = nil
	}
	return err
}

// 调用方必须持有 bs.mu。
func (bs *batchShaper) flushLocked() []byte {
	if len(bs.plaintext) == 0 {
		return nil
	}

	bs.timerStarted = false
	bs.timer.Stop()

	// 先按记录上限生成填充帧再增长，避免 AppendFrame 自行 realloc 漏出池外。
	if padFrame, ok := buildPaddingFrame(bs.paddingRNG, len(bs.plaintext), bs.recordCeiling); ok {
		bs.ensureCapacity(len(bs.plaintext) + protocol.FrameHeaderSize + len(padFrame.Payload))
		bs.plaintext = protocol.AppendFrame(bs.plaintext, padFrame)
	}

	// 流侧绝不能继续指向即将归还的 data，否则后续 append 会写进已入池的缓冲。
	data := bs.plaintext
	bs.plaintext = bytespool.Get(minRecordBufferSize)[:0]
	return data
}

// flushAndWrite 写出加密记录；调用方必须持有 bs.mu，I/O 期间临时释放。
func (bs *batchShaper) flushAndWrite(forceFlush bool) error {
	data := bs.flushLocked()
	if data == nil {
		return nil
	}

	// 序号必须与缓冲换出在同一临界区内分配：换出顺序才是线上顺序。
	seq := bs.writeSeq
	bs.writeSeq++
	bs.mu.Unlock()

	err := bs.writeRecordInOrder(seq, data, forceFlush)
	bytespool.MustPut(data[:cap(data)])

	bs.mu.Lock()
	if err != nil {
		bs.err = err
	}
	return err
}

func (bs *batchShaper) writeRecordInOrder(seq uint64, data []byte, forceFlush bool) error {
	bs.writeMu.Lock()
	for seq != bs.writeNext {
		bs.writeCond.Wait()
	}
	if bs.writeClosed.Load() {
		// 丢弃 Close 之后到达的记录，但必须推进序号并唤醒等待者，否则它们永远退出不了。
		bs.writeNext++
		bs.writeCond.Broadcast()
		bs.writeMu.Unlock()
		return nil
	}
	err := bs.writer.WriteRecord(data)
	if err == nil && forceFlush {
		bs.writer.Flush()
	}
	bs.writeNext++
	bs.writeCond.Broadcast()
	bs.writeMu.Unlock()
	return err
}

// 调用方不得持有 bs.mu，取锁由本方法负责。
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
			log.Debug("[SHAPER] timer flush aborted, stream closed", "err", err)
			return
		}
		log.Info("[SHAPER] timer flush error", "err", err)
	}
}

func isClosedStreamError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	// "http2: stream closed" 是标准库未导出的哨兵错误，只能字符串匹配。
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
