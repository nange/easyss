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
		// CSPRNG 失败会让 cover/padding 内容退化为确定性流——
		// 这对流量伪装层是致命的。应快速失败，而不是在零种子下静默运行。
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

// maxBatchWindowMS 限制批处理延迟，下方的 cover 流量参数没有对应的配置
// 字段：它们是伪装层的固定属性，在此处定义为唯一事实来源。
const (
	maxBatchWindowMS = 10

	defaultCoverIdleTimeoutMS = 300
	defaultCoverMinSize       = 128
	defaultCoverMaxSize       = 1500
)

// Normalize 应用所有构造路径共享的默认值和边界，使有效的整形器设置只有
// 一处定义，而不再由客户端配置层、服务端 handler 和 New 各自重复钳制。
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
	// 钳制到记录上限：Frame.Length 是 uint16，且 cover payload 必须放得进一条
	// 记录（否则会被整形器的单帧校验拒绝）。配置错误的预算上限绝不能造成这种
	// 后果。注意这里不能用 protocol.MaxUDPDataSize——它是 UDP 数据报的读缓冲
	// 上限，比记录上限紧得多，会把合法的 cover 配置一并削掉。
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

// BuildPaddingFrame 返回一个适合追加到当前明文缓冲区的 PADDING 帧。
// 填充大小根据 totalSize 通过分级算法推导，瞄准常见的记录大小区间，
// 以掩盖真实 payload 长度。
//
// budget 是这条记录可用的总空间（含帧头），<=0 表示按线上格式上限
// protocol.MaxReadRecordPlaintext 计算。调用方传入自己缓冲区的实际容量，可以在
// 缓冲尚未增长到上限时也做一次判断，而不是先生成再丢弃。
//
// 返回的 bool 表示是否生成了填充。当算法判定无需填充，或帧会超出 budget
// （以及线上格式上限）时为 false。
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
	// 包级 RNG 在多个流之间共享；math/rand/v2 的随机源不适合并发使用，
	// 因此用互斥锁保护填充操作。
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
		// 确保至少有 1 字节填充：零长度填充无法掩盖任何信息，
		// 还会让调用方的 ok=false 结果变得不确定。
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
