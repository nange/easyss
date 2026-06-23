package shaper

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/util/bytespool"
)

type batchShaper struct {
	writer       *crypto.RecordWriter
	frames       []protocol.Frame
	timer        *time.Timer
	mu           sync.Mutex
	batchSize    int
	maxChunkSize int
	window       time.Duration
	timerStarted bool
	closing      atomic.Bool
	err          error
	cover        *coverInjector
}

func NewLight(writer *crypto.RecordWriter, cfg Config) Shaper {
	window := time.Duration(cfg.BatchWindowMS) * time.Millisecond
	if window <= 0 {
		window = 3 * time.Millisecond
	}
	if window > 10*time.Millisecond {
		window = 10 * time.Millisecond
	}

	bs := &batchShaper{
		writer:       writer,
		maxChunkSize: protocol.MaxPlainRecordSize,
		window:       window,
	}
	bs.timer = time.AfterFunc(window, bs.onTimer)
	bs.timer.Stop()

	bs.cover = newCoverInjector(cfg.Cover, bs.injectCoverFrame, bs.isClosing)
	return bs
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
	if bs.batchSize > 0 && bs.batchSize+frameSize > bs.maxChunkSize {
		if err := bs.flush(); err != nil {
			return err
		}
	}

	bs.frames = append(bs.frames, f)
	bs.batchSize += frameSize

	if bs.batchSize >= bs.maxChunkSize {
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
	bs.mu.Unlock()
	if err != nil {
		return err
	}
	return nil
}

func (bs *batchShaper) flush() error {
	if len(bs.frames) == 0 {
		return nil
	}

	bs.timerStarted = false
	bs.timer.Stop()

	padFrames := BuildPaddingFrames(bs.batchSize)
	padSize := 0
	for _, f := range padFrames {
		padSize += f.EncodedLen()
	}
	plaintextSize := bs.batchSize
	if bs.batchSize+padSize <= bs.maxChunkSize {
		bs.frames = append(bs.frames, padFrames...)
		plaintextSize += padSize
	}

	plaintext := bytespool.Get(plaintextSize)
	defer bytespool.MustPut(plaintext)
	plaintext = protocol.EncodeFramesToBuf(bs.frames, plaintext)
	if err := bs.writer.WriteRecord(plaintext); err != nil {
		bs.err = err
		return err
	}

	bs.frames = bs.frames[:0]
	bs.batchSize = 0
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
	if bs.batchSize > 0 && bs.batchSize+frameSize > bs.maxChunkSize {
		if err := bs.flush(); err != nil {
			return err
		}
	}

	bs.frames = append(bs.frames, f)
	bs.batchSize += frameSize

	if bs.batchSize >= bs.maxChunkSize {
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
