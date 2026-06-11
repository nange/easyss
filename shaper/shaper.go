package shaper

import (
	cryptorand "crypto/rand"
	"math/big"

	"github.com/nange/easyss/v3/protocol"
)

type Shaper interface {
	PushFrame(f protocol.Frame) error
	Flush() error
	Close() error
}

type Config struct {
	Mode          string
	BatchWindowMS int
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
