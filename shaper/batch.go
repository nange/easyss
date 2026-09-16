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
	writer         *crypto.RecordWriter
	plaintext      []byte
	timer          *time.Timer
	mu             sync.Mutex
	writeMu        sync.Mutex // 跨 goroutine 串行化 WriteRecord 调用
	maxChunkSize   int
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
func New(writer *crypto.RecordWriter, cfg Config) Shaper {
	cfg = cfg.Normalize()

	bs := &batchShaper{
		writer:         writer,
		plaintext:      bytespool.Get(protocol.MaxPlainRecordSize)[:0],
		maxChunkSize:   protocol.MaxPlainRecordSize,
		flushThreshold: protocol.MaxPlainRecordSize * 9 / 10,
		window:         time.Duration(cfg.BatchWindowMS) * time.Millisecond,
	}
	bs.timer = time.AfterFunc(bs.window, bs.onTimer)
	bs.timer.Stop()

	bs.cover = newCoverInjector(cfg.Cover, bs.injectCoverFrame, bs.isClosing)
	return bs
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

// appendFrameLocked 将指定类型的帧追加到明文缓冲区：当记录即将溢出时
// 预冲刷，达到阈值时后冲刷，否则重新启动批处理定时器。
// putPayload 标记来自 bytespool 的 payload，追加完成后必须归还。
// 调用方必须持有 bs.mu。
func (bs *batchShaper) appendFrameLocked(ftype protocol.FrameType, payload []byte, putPayload bool) error {
	frameSize := protocol.FrameHeaderSize + len(payload)
	if frameSize > bs.maxChunkSize {
		if putPayload {
			bs.putPooledPayload(payload)
		}
		return fmt.Errorf("shaper: frame size %d exceeds max record size %d", frameSize, bs.maxChunkSize)
	}

	// 若追加会导致记录溢出，则预先冲刷。
	if len(bs.plaintext) > 0 && len(bs.plaintext)+frameSize > bs.maxChunkSize {
		if err := bs.flushAndWrite(false); err != nil {
			// 该帧从未被追加，因此在此归还池化 payload：没有其他人会归还它。
			if putPayload {
				bs.putPooledPayload(payload)
			}
			return err
		}
	}

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

	if padFrame, ok := BuildPaddingFrame(len(bs.plaintext)); ok {
		bs.plaintext = protocol.AppendFrame(bs.plaintext, padFrame)
	}

	// 交换缓冲区：将数据交给 I/O，分配一个全新缓冲区，
	// 以便并发的 PushData / PushFrame 继续接收数据。
	data := bs.plaintext
	bs.plaintext = bytespool.Get(protocol.MaxPlainRecordSize)[:0]
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
