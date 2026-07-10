package shaper

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util/bytespool"
)

type batchShaper struct {
	writer         *crypto.RecordWriter
	plaintext      []byte
	timer          *time.Timer
	mu             sync.Mutex
	maxChunkSize   int
	flushThreshold int
	window         time.Duration
	timerStarted   bool
	closing        atomic.Bool
	err            error
	cover          *coverInjector
}

func New(writer *crypto.RecordWriter, cfg Config) Shaper {
	window := time.Duration(cfg.BatchWindowMS) * time.Millisecond
	if window <= 0 {
		window = 3 * time.Millisecond
	}
	if window > 10*time.Millisecond {
		window = 10 * time.Millisecond
	}

	bs := &batchShaper{
		writer:         writer,
		plaintext:      bytespool.Get(protocol.MaxPlainRecordSize)[:0],
		maxChunkSize:   protocol.MaxPlainRecordSize,
		flushThreshold: protocol.MaxPlainRecordSize * 9 / 10,
		window:         window,
	}
	bs.timer = time.AfterFunc(window, bs.onTimer)
	bs.timer.Stop()

	bs.cover = newCoverInjector(cfg.Cover, bs.injectCoverFrame, bs.isClosing)
	return bs
}

// PushData adds raw data as a DATA frame. Returns without holding the lock.
func (bs *batchShaper) PushData(data []byte) error {
	bs.mu.Lock()

	if bs.closing.Load() {
		bs.mu.Unlock()
		return nil
	}
	if bs.err != nil {
		err := bs.err
		bs.mu.Unlock()
		return err
	}

	frameSize := protocol.FrameHeaderSize + len(data)
	if frameSize > bs.maxChunkSize {
		bs.mu.Unlock()
		return fmt.Errorf("shaper: data size %d exceeds max record size %d", frameSize, bs.maxChunkSize)
	}

	if bs.cover != nil {
		bs.cover.addBudget(frameSize)
	}

	// Pre-flush if appending would overflow the record.
	if len(bs.plaintext) > 0 && len(bs.plaintext)+frameSize > bs.maxChunkSize {
		bs.mu.Unlock()
		if err := bs.flush(); err != nil {
			return err
		}
		bs.mu.Lock()
	}

	bs.plaintext = appendFrameHeader(bs.plaintext, protocol.FrameDATA, data)
	bs.plaintext = append(bs.plaintext, data...)

	// Post-flush if threshold reached.
	if len(bs.plaintext) >= bs.flushThreshold {
		bs.mu.Unlock()
		return bs.flush()
	}

	if !bs.timerStarted {
		bs.timerStarted = true
		bs.timer.Reset(bs.window)
	}
	bs.mu.Unlock()
	return nil
}

// PushFrame adds a pre-built frame (FIN, RST, COVER, etc.). Returns without holding the lock.
func (bs *batchShaper) PushFrame(f protocol.Frame) error {
	bs.mu.Lock()

	if bs.closing.Load() {
		bs.mu.Unlock()
		return nil
	}
	if bs.err != nil {
		err := bs.err
		bs.mu.Unlock()
		return err
	}

	if bs.cover != nil && f.Type != protocol.FrameCOVER && f.Type != protocol.FramePADDING {
		bs.cover.addBudget(f.EncodedLen())
	}

	frameSize := f.EncodedLen()
	if frameSize > bs.maxChunkSize {
		bs.mu.Unlock()
		return fmt.Errorf("shaper: frame size %d exceeds max record size %d", frameSize, bs.maxChunkSize)
	}

	// Pre-flush if appending would overflow the record.
	if len(bs.plaintext) > 0 && len(bs.plaintext)+frameSize > bs.maxChunkSize {
		bs.mu.Unlock()
		if err := bs.flush(); err != nil {
			return err
		}
		bs.mu.Lock()
	}

	bs.plaintext = appendFrameHeader(bs.plaintext, f.Type, f.Payload)
	bs.plaintext = append(bs.plaintext, f.Payload...)

	if f.Type == protocol.FrameCOVER && len(f.Payload) > 0 {
		bytespool.MustPut(f.Payload)
	}

	// Post-flush if threshold reached.
	if len(bs.plaintext) >= bs.flushThreshold {
		bs.mu.Unlock()
		return bs.flush()
	}

	if !bs.timerStarted {
		bs.timerStarted = true
		bs.timer.Reset(bs.window)
	}
	bs.mu.Unlock()
	return nil
}

// Flush triggers an immediate flush. Does not require the caller to hold the lock.
func (bs *batchShaper) Flush() error {
	return bs.flush()
}

// Close stops cover traffic, flushes remaining data, and returns the buffer to the pool.
func (bs *batchShaper) Close() error {
	bs.mu.Lock()
	bs.closing.Store(true)
	if bs.cover != nil {
		bs.cover.stop()
	}
	bs.mu.Unlock()

	err := bs.flush()

	bs.mu.Lock()
	plaintextBacking := bs.plaintext[:cap(bs.plaintext)]
	bs.plaintext = nil
	bs.mu.Unlock()

	if plaintextBacking != nil {
		bytespool.MustPut(plaintextBacking)
	}
	return err
}

// flush acquires the lock, swaps the buffer, releases the lock before I/O,
// then writes the encrypted record. Caller must NOT hold bs.mu.
func (bs *batchShaper) flush() error {
	bs.mu.Lock()
	if len(bs.plaintext) == 0 {
		bs.mu.Unlock()
		return nil
	}

	bs.timerStarted = false
	bs.timer.Stop()

	padSize := computePadPayloadSize(len(bs.plaintext))
	if padSize > 0 && len(bs.plaintext)+protocol.FrameHeaderSize+padSize <= bs.maxChunkSize {
		var header [protocol.FrameHeaderSize]byte
		header[0] = byte(protocol.FramePADDING)
		binary.BigEndian.PutUint16(header[1:3], uint16(padSize))
		bs.plaintext = append(bs.plaintext, header[:]...)
		off := len(bs.plaintext)
		bs.plaintext = append(bs.plaintext, make([]byte, padSize)...)
		_, _ = cryptorand.Read(bs.plaintext[off:])
		stats.RecordPaddingBytes(padSize)
	}

	// Swap buffer: hand off data for I/O, allocate a fresh buffer so
	// concurrent PushData / PushFrame can keep accepting data.
	data := bs.plaintext
	bs.plaintext = bytespool.Get(protocol.MaxPlainRecordSize)[:0]

	bs.mu.Unlock()

	err := bs.writer.WriteRecord(data)
	bytespool.MustPut(data[:cap(data)])

	if err != nil {
		bs.mu.Lock()
		bs.err = err
		bs.mu.Unlock()
	}
	return err
}

func (bs *batchShaper) onTimer() {
	bs.mu.Lock()
	bs.timerStarted = false
	bs.mu.Unlock()
	_ = bs.flush()
}

func (bs *batchShaper) injectCoverFrame(f protocol.Frame) error {
	bs.mu.Lock()

	if bs.closing.Load() || bs.err != nil {
		bs.mu.Unlock()
		return nil
	}

	frameSize := f.EncodedLen()

	// Pre-flush if appending would overflow the record.
	if len(bs.plaintext) > 0 && len(bs.plaintext)+frameSize > bs.maxChunkSize {
		bs.mu.Unlock()
		if err := bs.flush(); err != nil {
			return err
		}
		bs.mu.Lock()
	}

	bs.plaintext = appendFrameHeader(bs.plaintext, f.Type, f.Payload)
	bs.plaintext = append(bs.plaintext, f.Payload...)

	if f.Type == protocol.FrameCOVER && len(f.Payload) > 0 {
		bytespool.MustPut(f.Payload)
	}

	// Post-flush if threshold reached.
	if len(bs.plaintext) >= bs.flushThreshold {
		bs.mu.Unlock()
		return bs.flush()
	}

	if !bs.timerStarted {
		bs.timerStarted = true
		bs.timer.Reset(bs.window)
	}
	bs.mu.Unlock()
	return nil
}

func (bs *batchShaper) isClosing() bool {
	return bs.closing.Load()
}

func appendFrameHeader(buf []byte, ftype protocol.FrameType, payload []byte) []byte {
	var header [protocol.FrameHeaderSize]byte
	header[0] = byte(ftype)
	binary.BigEndian.PutUint16(header[1:3], uint16(len(payload)))
	return append(buf, header[:]...)
}
