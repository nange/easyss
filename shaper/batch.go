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

func (bs *batchShaper) PushData(data []byte) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closing.Load() {
		return nil
	}
	if bs.err != nil {
		return bs.err
	}

	frameSize := protocol.FrameHeaderSize + len(data)
	if frameSize > bs.maxChunkSize {
		return fmt.Errorf("shaper: data size %d exceeds max record size %d", frameSize, bs.maxChunkSize)
	}

	if bs.cover != nil {
		bs.cover.addBudget(frameSize)
	}

	if len(bs.plaintext) > 0 && len(bs.plaintext)+frameSize > bs.maxChunkSize {
		if err := bs.flush(); err != nil {
			return err
		}
	}

	bs.plaintext = appendFrameHeader(bs.plaintext, protocol.FrameDATA, data)
	bs.plaintext = append(bs.plaintext, data...)

	if len(bs.plaintext) >= bs.flushThreshold {
		return bs.flush()
	}
	if !bs.timerStarted {
		bs.timerStarted = true
		bs.timer.Reset(bs.window)
	}

	return nil
}

func (bs *batchShaper) PushFrame(f protocol.Frame) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closing.Load() {
		return nil
	}
	if bs.err != nil {
		return bs.err
	}

	if bs.cover != nil && f.Type != protocol.FrameCOVER && f.Type != protocol.FramePADDING {
		bs.cover.addBudget(f.EncodedLen())
	}

	frameSize := f.EncodedLen()
	if frameSize > bs.maxChunkSize {
		return fmt.Errorf("shaper: frame size %d exceeds max record size %d", frameSize, bs.maxChunkSize)
	}
	if len(bs.plaintext) > 0 && len(bs.plaintext)+frameSize > bs.maxChunkSize {
		if err := bs.flush(); err != nil {
			return err
		}
	}

	bs.plaintext = appendFrameHeader(bs.plaintext, f.Type, f.Payload)
	bs.plaintext = append(bs.plaintext, f.Payload...)

	if f.Type == protocol.FrameCOVER && len(f.Payload) > 0 {
		bytespool.MustPut(f.Payload)
	}

	if len(bs.plaintext) >= bs.flushThreshold {
		return bs.flush()
	}
	if !bs.timerStarted {
		bs.timerStarted = true
		bs.timer.Reset(bs.window)
	}

	return nil
}

func (bs *batchShaper) Flush() error {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return bs.flush()
}

func (bs *batchShaper) Close() error {
	bs.mu.Lock()
	bs.closing.Store(true)
	if bs.cover != nil {
		bs.cover.stop()
	}
	err := bs.flush()
	plaintextBacking := bs.plaintext[:cap(bs.plaintext)]
	bs.plaintext = nil
	bs.mu.Unlock()

	if plaintextBacking != nil {
		bytespool.MustPut(plaintextBacking)
	}
	if err != nil {
		return err
	}
	return nil
}

func (bs *batchShaper) flush() error {
	if len(bs.plaintext) == 0 {
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

	if err := bs.writer.WriteRecord(bs.plaintext); err != nil {
		bs.err = err
		return err
	}

	bs.plaintext = bs.plaintext[:0]
	return nil
}

func (bs *batchShaper) onTimer() {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.timerStarted = false
	_ = bs.flush()
}

func (bs *batchShaper) injectCoverFrame(f protocol.Frame) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closing.Load() || bs.err != nil {
		return nil
	}

	frameSize := f.EncodedLen()
	if len(bs.plaintext) > 0 && len(bs.plaintext)+frameSize > bs.maxChunkSize {
		if err := bs.flush(); err != nil {
			return err
		}
	}

	bs.plaintext = appendFrameHeader(bs.plaintext, f.Type, f.Payload)
	bs.plaintext = append(bs.plaintext, f.Payload...)

	if f.Type == protocol.FrameCOVER && len(f.Payload) > 0 {
		bytespool.MustPut(f.Payload)
	}

	if len(bs.plaintext) >= bs.flushThreshold {
		return bs.flush()
	}
	if !bs.timerStarted {
		bs.timerStarted = true
		bs.timer.Reset(bs.window)
	}

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
