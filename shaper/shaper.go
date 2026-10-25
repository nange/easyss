package shaper

import (
	cryptorand "crypto/rand"
	"math/rand/v2"
	"sync"

	"github.com/nange/easyss/v3/config"
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

// Cover 是 cover traffic 的参数：BudgetRatio/BudgetCap 是配置项，其余是伪装层固定属性。
// 匿名嵌入 Config 后 encoding/json 会把配置项平铺成 shaper.* 的线格式，给嵌入字段加 tag 会变回嵌套。
type Cover struct {
	BudgetRatio float64 `json:"cover_budget_ratio"` // cover 流量相对真实流量的预算比例，0.0-1.0（默认 0.03）
	IdleTimeout int     `json:"-"`                  // 发送 cover 帧前的空闲超时（毫秒）（默认 300）
	MinSize     int     `json:"-"`                  // cover 帧 payload 最小尺寸（字节）（默认 128）
	MaxSize     int     `json:"-"`                  // cover 帧 payload 最大尺寸（字节）（默认 1500）
	BudgetCap   int     `json:"cover_budget_cap"`   // 累计 cover 预算上限（字节），<=0 时使用默认值（16KB）
}

// Config 同时是 shaper.* 的线格式（客户端与服务端共用）与运行时配置。
type Config struct {
	BatchWindowMS int `json:"batch_window_ms"`
	Cover
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
		c.BatchWindowMS = config.DefaultBatchWindowMS
	}
	if c.BatchWindowMS > maxBatchWindowMS {
		c.BatchWindowMS = maxBatchWindowMS
	}

	if c.BudgetRatio <= 0 || c.BudgetRatio > 1 {
		c.BudgetRatio = config.DefaultCoverBudgetRatio
	}
	if c.BudgetCap <= 0 {
		c.BudgetCap = config.DefaultCoverBudgetCap
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = defaultCoverIdleTimeoutMS
	}
	if c.MinSize <= 0 {
		c.MinSize = defaultCoverMinSize
	}
	if c.MaxSize <= 0 {
		c.MaxSize = defaultCoverMaxSize
	}
	// 钳制到记录上限：Frame.Length 是 uint16，cover payload 必须放得进一条记录，
	// 否则会被单帧校验拒绝。不能用 protocol.MaxUDPDataSize，它会把合法 cover 配置一并削掉。
	maxFramePayload := protocol.MaxWriteRecordPlaintext - protocol.FrameHeaderSize
	if c.MinSize > maxFramePayload {
		c.MinSize = maxFramePayload
	}
	if c.MaxSize > maxFramePayload {
		c.MaxSize = maxFramePayload
	}
	if c.MaxSize < c.MinSize {
		c.MaxSize = c.MinSize
	}
	return c
}

// BuildPaddingFrame 生成 PADDING 帧，把记录尺寸推向常见档位以掩盖真实 payload 长度。
// budget 是这条记录可用的总空间（含帧头），≤0 按线上格式上限计算；
// 超出 budget 或无需填充时返回 false。
func BuildPaddingFrame(totalSize, budget int) (protocol.Frame, bool) {
	frame, ok := newPaddingFrame(totalSize, budget)
	if !ok {
		return protocol.Frame{}, false
	}
	// 包级 RNG 只服务无法从 Shaper 拿到实例的调用方；高吞吐的 batchShaper 用自己的 RNG。
	paddingRNGMu.Lock()
	_, _ = paddingRNG.Read(frame.Payload)
	paddingRNGMu.Unlock()
	return frame, true
}

// buildPaddingFrame 用调用方传入的 RNG 填充；batchShaper 在 bs.mu 下调用，无需再加锁。
func buildPaddingFrame(rng *rand.ChaCha8, totalSize, budget int) (protocol.Frame, bool) {
	frame, ok := newPaddingFrame(totalSize, budget)
	if !ok {
		return protocol.Frame{}, false
	}
	_, _ = rng.Read(frame.Payload)
	return frame, true
}

func newPaddingFrame(totalSize, budget int) (protocol.Frame, bool) {
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
	return protocol.NewFramePADDING(uint16(padSize)), true
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
