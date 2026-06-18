package shaper

import (
	cryptorand "crypto/rand"
	"math/big"

	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/stats"
)

type Shaper interface {
	PushFrame(f protocol.Frame) error
	Flush() error
	Close() error
}

type CoverConfig struct {
	BudgetRatio float64 // cover traffic budget ratio to real traffic, 0.0-1.0 (default 0.10)
	IdleTimeout int     // idle timeout in ms before sending cover frames (default 100)
	MinSize     int     // min cover frame payload size in bytes (default 64)
	MaxSize     int     // max cover frame payload size in bytes (default 1500)
}

type Config struct {
	BatchWindowMS int
	Cover         CoverConfig
}

type ShaperFunc func(frames []protocol.Frame) []protocol.Frame

func BuildPaddingFrames(totalSize int) []protocol.Frame {
	var target int
	switch {
	case totalSize <= 128:
		target = 128 + randomInt(128)
	case totalSize <= 512:
		target = 512 + randomInt(512)
	case totalSize <= 1500:
		target = 1500 + randomInt(500)
	default:
		add := randomInt(64)
		target = totalSize + add
	}

	if target <= totalSize {
		return nil
	}

	padSize := target - totalSize
	stats.RecordPaddingBytes(padSize)
	frame := protocol.NewFramePADDING(uint16(padSize))
	_, _ = cryptorand.Read(frame.Payload)
	return []protocol.Frame{frame}
}

func randomInt(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}
