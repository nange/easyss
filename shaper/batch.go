package shaper

import (
	"fmt"
	"sync"
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
	closing      bool
	err          error
}

func NewLight(writer *crypto.RecordWriter, cfg Config) Shaper {
	window := time.Duration(cfg.BatchWindowMS) * time.Millisecond
	if window <= 0 {
		window = 5 * time.Millisecond
	}

	bs := &batchShaper{
		writer:       writer,
		maxChunkSize: protocol.MaxPlainRecordSize,
		window:       window,
	}
	bs.timer = time.AfterFunc(window, bs.onTimer)
	bs.timer.Stop()
	return bs
}

func (bs *batchShaper) PushFrame(f protocol.Frame) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closing {
		return nil
	}
	if bs.err != nil {
		return bs.err
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
	defer bs.mu.Unlock()
	if err := bs.flush(); err != nil {
		return err
	}
	bs.closing = true
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
	plaintext = protocol.EncodeFramesToBuf(bs.frames, plaintext)
	if err := bs.writer.WriteRecord(plaintext); err != nil {
		bs.err = err
		return err
	}
	bytespool.MustPut(plaintext)

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
