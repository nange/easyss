package shaper

import (
	cryptorand "crypto/rand"
	"math/rand/v2"
	"sync"

	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/stats"
)

func newSeededChaCha8() *rand.ChaCha8 {
	var seed [32]byte
	if _, err := cryptorand.Read(seed[:]); err != nil {
		// A CSPRNG failure would degenerate cover/padding content into a
		// deterministic stream — fatal for a traffic-camouflage layer. Fail
		// fast instead of silently running with a zero seed.
		panic("shaper: crypto/rand unavailable: " + err.Error())
	}
	return rand.NewChaCha8(seed)
}

var (
	paddingRNG   = newSeededChaCha8()
	paddingRNGMu sync.Mutex
)

type Shaper interface {
	PushFrame(f protocol.Frame) error
	PushData(data []byte) error
	Flush() error
	Close() error
}

type CoverConfig struct {
	BudgetRatio float64 // cover traffic budget ratio to real traffic, 0.0-1.0 (default 0.03)
	IdleTimeout int     // idle timeout in ms before sending cover frames (default 300)
	MinSize     int     // min cover frame payload size in bytes (default 128)
	MaxSize     int     // max cover frame payload size in bytes (default 1500)
	BudgetCap   int     // max accumulated cover budget in bytes, <=0 uses the default (16KB)
}

type Config struct {
	BatchWindowMS int
	Cover         CoverConfig
}

// maxBatchWindowMS bounds the batching delay, and the cover-traffic knobs
// below have no config field: they are fixed properties of the camouflage
// layer, defined here as the single source of truth.
const (
	maxBatchWindowMS = 10

	defaultCoverIdleTimeoutMS = 300
	defaultCoverMinSize       = 128
	defaultCoverMaxSize       = 1500
)

// Normalize applies the defaults and bounds every construction path shares, so
// the effective shaper settings have exactly one definition instead of being
// re-clamped by the client config layer, the server handler and New.
func (c Config) Normalize() Config {
	if c.BatchWindowMS <= 0 {
		c.BatchWindowMS = sharedconfig.DefaultBatchWindowMS
	}
	if c.BatchWindowMS > maxBatchWindowMS {
		c.BatchWindowMS = maxBatchWindowMS
	}

	if c.Cover.BudgetRatio <= 0 || c.Cover.BudgetRatio > 1 {
		c.Cover.BudgetRatio = sharedconfig.DefaultCoverBudgetRatio
	}
	if c.Cover.BudgetCap <= 0 {
		c.Cover.BudgetCap = sharedconfig.DefaultCoverBudgetCap
	}
	if c.Cover.IdleTimeout <= 0 {
		c.Cover.IdleTimeout = defaultCoverIdleTimeoutMS
	}
	if c.Cover.MinSize <= 0 {
		c.Cover.MinSize = defaultCoverMinSize
	}
	if c.Cover.MaxSize <= 0 {
		c.Cover.MaxSize = defaultCoverMaxSize
	}
	// Clamp to the wire format: Frame.Length is uint16 and cover payloads come
	// from the bytes pool, so an oversized value would corrupt the record
	// stream. A misconfigured budget cap must not be able to do that.
	if c.Cover.MinSize > protocol.MaxUDPDataSize {
		c.Cover.MinSize = protocol.MaxUDPDataSize
	}
	if c.Cover.MaxSize > protocol.MaxUDPDataSize {
		c.Cover.MaxSize = protocol.MaxUDPDataSize
	}
	if c.Cover.MaxSize < c.Cover.MinSize {
		c.Cover.MaxSize = c.Cover.MinSize
	}
	return c
}

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
	// The package-level RNG is shared across streams; math/rand/v2 sources
	// are not safe for concurrent use, so guard the fill with a mutex.
	paddingRNGMu.Lock()
	_, _ = paddingRNG.Read(frame.Payload)
	paddingRNGMu.Unlock()
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
		// Ensure at least 1 byte of padding: a zero-length pad masks nothing
		// and would make the caller's ok=false result nondeterministic.
		add := 1 + randomInt(63)
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
