package shaper

import (
	cryptorand "crypto/rand"
	"math/rand/v2"

	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/stats"
)

func newSeededChaCha8() *rand.ChaCha8 {
	var seed [32]byte
	_, _ = cryptorand.Read(seed[:])
	return rand.NewChaCha8(seed)
}

var paddingRNG = newSeededChaCha8()

type Shaper interface {
	PushFrame(f protocol.Frame) error
	PushData(data []byte) error
	Flush() error
	Close() error
}

type CoverConfig struct {
	BudgetRatio float64 // cover traffic budget ratio to real traffic, 0.0-1.0 (default 0.10)
	IdleTimeout int     // idle timeout in ms before sending cover frames (default 300)
	MinSize     int     // min cover frame payload size in bytes (default 128)
	MaxSize     int     // max cover frame payload size in bytes (default 1500)
	BudgetCap   int     // max accumulated cover budget in bytes, 0 means unlimited (default 128KB)
}

type Config struct {
	BatchWindowMS int
	Cover         CoverConfig
}

type ShaperFunc func(frames []protocol.Frame) []protocol.Frame

// BuildPaddingFrame returns a single PADDING frame suitable for appending to
// the current plaintext buffer. The padding size is derived from totalSize
// using a tiered algorithm that targets common record-size ranges to mask
// the true payload length.
//
// The returned bool indicates whether padding was produced. It is false when
// the algorithm decides padding is unnecessary or when the frame would exceed
// MaxPlainRecordSize.
func BuildPaddingFrame(totalSize int) (protocol.Frame, bool) {
	padSize := computePadPayloadSize(totalSize)
	if padSize <= 0 {
		return protocol.Frame{}, false
	}
	if totalSize+protocol.FrameHeaderSize+padSize > protocol.MaxPlainRecordSize {
		return protocol.Frame{}, false
	}

	stats.RecordPaddingBytes(padSize)
	frame := protocol.NewFramePADDING(uint16(padSize))
	_, _ = paddingRNG.Read(frame.Payload)
	return frame, true
}

func computePadPayloadSize(totalSize int) int {
	var target int
	switch {
	case totalSize <= 128:
		target = 128 + randomInt(256)
	case totalSize <= 512:
		target = 512 + randomInt(256)
	case totalSize <= 1500:
		target = 1500 + randomInt(500)
	default:
		add := randomInt(64)
		target = totalSize + add
	}

	if target <= totalSize {
		return 0
	}
	return target - totalSize
}

func randomInt(n int) int {
	if n <= 0 {
		return 0
	}
	return rand.IntN(n)
}
