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
		// CSPRNG 失败会让 cover/padding 退化为确定性流，对伪装层是致命的，直接 panic。
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
	BudgetRatio float64 // cover 流量相对真实流量的预算比例，0.0-1.0（默认 0.03）
	IdleTimeout int     // 发送 cover 帧前的空闲超时（毫秒）（默认 300）
	MinSize     int     // cover 帧 payload 最小尺寸（字节）（默认 128）
	MaxSize     int     // cover 帧 payload 最大尺寸（字节）（默认 1500）
	BudgetCap   int     // 累计 cover 预算上限（字节），<=0 时使用默认值（16KB）
}

type Config struct {
	BatchWindowMS int
	Cover         CoverConfig
}

// maxBatchWindowMS 限制批处理延迟；下面的 cover 参数是伪装层的固定属性，
// 在此处定义为唯一事实来源。
const (
	maxBatchWindowMS = 10

	defaultCoverIdleTimeoutMS = 300
	defaultCoverMinSize       = 128
	defaultCoverMaxSize       = 1500
)

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
	// 钳制到记录上限：Frame.Length 是 uint16，cover payload 必须放得进一条记录，
	// 否则会被单帧校验拒绝。不能用 protocol.MaxUDPDataSize，它会把合法 cover 配置一并削掉。
	maxFramePayload := protocol.MaxWriteRecordPlaintext - protocol.FrameHeaderSize
	if c.Cover.MinSize > maxFramePayload {
		c.Cover.MinSize = maxFramePayload
	}
	if c.Cover.MaxSize > maxFramePayload {
		c.Cover.MaxSize = maxFramePayload
	}
	if c.Cover.MaxSize < c.Cover.MinSize {
		c.Cover.MaxSize = c.Cover.MinSize
	}
	return c
}

// BuildPaddingFrame 生成 PADDING 帧，把记录尺寸推向常见档位以掩盖真实 payload 长度。
// budget 是这条记录可用的总空间（含帧头），≤0 按线上格式上限计算；
// 超出 budget 或无需填充时返回 false。
func BuildPaddingFrame(totalSize, budget int) (protocol.Frame, bool) {
	if budget <= 0 || budget > protocol.MaxReadRecordPlaintext {
		budget = protocol.MaxReadRecordPlaintext
	}
	padSize := computePadPayloadSize(totalSize)
	if padSize <= 0 {
		return protocol.Frame{}, false
	}
	if totalSize+protocol.FrameHeaderSize+padSize > budget {
		return protocol.Frame{}, false
	}

	stats.RecordPaddingBytes(padSize)
	frame := protocol.NewFramePADDING(uint16(padSize))
	// math/rand/v2 的随机源不适合并发使用，包级 RNG 由互斥锁保护。
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
		// 至少 1 字节填充：零长度填充掩盖不了任何信息。
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
