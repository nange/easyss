package shaper

import (
	"encoding/binary"
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
	writeMu        sync.Mutex // serializes WriteRecord calls across goroutines
	maxChunkSize   int
	flushThreshold int
	window         time.Duration
	timerStarted   bool
	closing        atomic.Bool
	writeClosed    atomic.Bool // set after Close's flush; prevents writes after handler returns
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

// PushFrame adds a pre-built frame (FIN, RST, COVER, etc.). Returns without holding the lock.
func (bs *batchShaper) PushFrame(f protocol.Frame) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closing.Load() {
		return nil
	}
	if bs.err != nil {
		return bs.err
	}

	// Normalize the frame so the capacity check and the wire header always
	// agree: the header is written from len(Payload), while the pre-flush
	// check uses EncodedLen — a mismatched Frame could otherwise bypass the
	// record-size guard and corrupt the stream.
	if len(f.Payload) > math.MaxUint16 {
		return fmt.Errorf("shaper: frame payload too large: %d", len(f.Payload))
	}
	f.Length = uint16(len(f.Payload))

	if bs.cover != nil && f.Type != protocol.FrameCOVER && f.Type != protocol.FramePADDING {
		bs.cover.addBudget(f.EncodedLen())
	}
	return bs.appendFrameLocked(f.Type, f.Payload, f.Type == protocol.FrameCOVER)
}

// appendFrameLocked appends a frame of the given type to the plaintext
// buffer: it pre-flushes when the record would overflow, post-flushes when
// the threshold is reached, and re-arms the batch timer otherwise.
// putPayload marks payloads that came from bytespool and must be returned
// once appended. Caller must hold bs.mu.
func (bs *batchShaper) appendFrameLocked(ftype protocol.FrameType, payload []byte, putPayload bool) error {
	frameSize := protocol.FrameHeaderSize + len(payload)
	if frameSize > bs.maxChunkSize {
		if putPayload {
			bs.putPooledPayload(payload)
		}
		return fmt.Errorf("shaper: frame size %d exceeds max record size %d", frameSize, bs.maxChunkSize)
	}

	// Pre-flush if appending would overflow the record.
	if len(bs.plaintext) > 0 && len(bs.plaintext)+frameSize > bs.maxChunkSize {
		if err := bs.flushAndWrite(false); err != nil {
			// The frame was never appended, so return the pooled payload
			// here: nobody else will.
			if putPayload {
				bs.putPooledPayload(payload)
			}
			return err
		}
	}

	bs.plaintext = appendFrameHeader(bs.plaintext, ftype, payload)
	bs.plaintext = append(bs.plaintext, payload...)

	if putPayload {
		bs.putPooledPayload(payload)
	}

	// Post-flush if threshold reached.
	if len(bs.plaintext) >= bs.flushThreshold {
		return bs.flushAndWrite(false)
	}

	bs.timerStarted = true
	bs.timer.Reset(bs.window)
	return nil
}

// putPooledPayload returns a cover payload to bytespool when it actually is
// a pool buffer (cap a power of two within the pool ceiling). A
// caller-provided heap slice would make MustPut panic on the power-of-two
// invariant, so such payloads are left to the GC.
func (bs *batchShaper) putPooledPayload(payload []byte) {
	if len(payload) > 0 && cap(payload) <= bytespool.MaxSize && cap(payload)&(cap(payload)-1) == 0 {
		bytespool.MustPut(payload)
	}
}

// Flush triggers an immediate flush. Does not require the caller to hold the lock.
func (bs *batchShaper) Flush() error {
	return bs.flush(true)
}

// Close stops cover traffic, flushes remaining data, and returns the buffer to the pool.
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

	// Serialize with writeMu: any flushAndWrite that acquires writeMu after
	// this point will see writeClosed and discard its data, preventing writes
	// to an already-finished HTTP handler. Flushes that acquired writeMu before
	// this point will complete normally; we block here until they finish.
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

// flushLocked stops the timer, appends padding, and swaps the plaintext buffer.
// Must be called with mu held. Returns the data to write, or nil if the buffer is empty.
func (bs *batchShaper) flushLocked() []byte {
	if len(bs.plaintext) == 0 {
		return nil
	}

	bs.timerStarted = false
	bs.timer.Stop()

	if padFrame, ok := BuildPaddingFrame(len(bs.plaintext)); ok {
		bs.plaintext = protocol.AppendFrame(bs.plaintext, padFrame)
	}

	// Swap buffer: hand off data for I/O, allocate a fresh buffer so
	// concurrent PushData / PushFrame can keep accepting data.
	data := bs.plaintext
	bs.plaintext = bytespool.Get(protocol.MaxPlainRecordSize)[:0]
	return data
}

// flushAndWrite flushes the current buffer and writes the encrypted record.
// Must be called with mu held. Temporarily releases mu during I/O and
// re-acquires it before returning. When forceFlush is true, an explicit
// HTTP/2 flush is triggered after the write to ensure immediate delivery.
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

// flush acquires the lock, flushes the buffer, and releases the lock.
// Caller must NOT hold bs.mu.
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
			// The peer already closed the stream (e.g. RST_STREAM/FIN while
			// the handler is still winding down the relay). The failed flush
			// is just the teardown path finishing, not a real error.
			log.Debug("[SHAPER] timer flush aborted, stream closed", "err", err)
			return
		}
		log.Info("[SHAPER] timer flush error", "err", err)
	}
}

// isClosedStreamError reports whether err indicates the underlying stream was
// already closed by the peer (HTTP/2 stream reset, closed pipe, closed
// connection). Such errors are benign during teardown: the peer has abandoned
// the stream and the failed flush is just the relay finishing.
func isClosedStreamError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	// "http2: stream closed" is an unexported sentinel in the stdlib, so it
	// can only be matched by string. The error chain is preserved by crypto
	// ("crypto: write record: ..."), so a substring match is sufficient.
	return strings.Contains(strings.ToLower(err.Error()), "stream closed")
}

func (bs *batchShaper) injectCoverFrame(f protocol.Frame) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if bs.closing.Load() || bs.err != nil {
		// Return the pooled payload so no buffer is leaked when the shaper
		// is already closed or failed.
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

func appendFrameHeader(buf []byte, ftype protocol.FrameType, payload []byte) []byte {
	var header [protocol.FrameHeaderSize]byte
	header[0] = byte(ftype)
	binary.BigEndian.PutUint16(header[1:3], uint16(len(payload)))
	return append(buf, header[:]...)
}
