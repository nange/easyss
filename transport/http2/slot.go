package http2

import (
	"net/http"
	"sync/atomic"
	"time"
)

// transportSlot 承载一条 HTTP/2 连接（一个通过 MaxConnsPerHost=1 固定到单条
// 连接上的标准库 http.Transport），以及调度器和连接生命周期所作用的状态。
type transportSlot struct {
	// idx 是槽位在调度器预分配数组中的稳定索引，构造时设置一次。
	// retire 会交换删除槽位，因此活跃位置与 idx 会分道扬镳；
	// idx 用于统计上报。
	idx int

	t      *http.Transport
	active atomic.Int32
	heavy  atomic.Int32 // 活跃 heavy 流数量（>= HeavyStreamThreshold 字节）
	// bytesRecv 是该槽位所有流累计下载的字节数；健康循环采样它以估算近期
	// 吞吐量。
	bytesRecv atomic.Int64
	// degraded 标记承载 heavy 流期间下载吞吐量持续低于降级阈值的槽位；
	// 新流会避开它，其空闲连接会被提前退役。
	degraded atomic.Bool

	// 连接轮换状态。
	expireAt  atomic.Int64 // 当前连接的 unix 纳秒截止时间（拨号时间 + 生命周期 + 抖动）
	connBytes atomic.Int64 // 当前连接在任一方向承载的字节数
	// expiring 标记连接超过生命周期或字节限制的槽位；新流避开它，其空闲
	// 连接会被关闭，使下一条流拨号建立新连接。新连接建立或轮换完成时清除。
	expiring atomic.Bool

	// 健康循环状态，仅由健康循环 goroutine 访问。
	lastBytes     int64
	lastHeavy     int // 上次观测到的 heavy 计数，跟踪 heavy 0->1 的转换
	lowCycles     int
	recoverCycles int

	// 探测状态，仅由健康循环 goroutine 访问。suspected 标记被动吞吐量低到
	// 值得用主动探测确认的槽位；probeLowCycles 统计连续慢探测次数；
	// lastProbeAt 执行探测冷却。
	suspected      bool
	probeLowCycles int
	lastProbeAt    time.Time
}

// resetRotation 清除连接已不存在的槽位的连接作用域状态（连接被 shrink/
// retire/rotation 关闭，或从未建立）：截止时间、承载字节数以及
// expiring/degraded 标记都回到"无连接"基线。expireAt 被清零而不是设置为
// 新的截止时间——rotationDue 只在 expireAt > 0 时触发，因此没有连接的
// 槽位永远不会被判定逾期。下次拨号调用 resetConn 设置真正的截止时间。
// grow 在重新激活预分配槽位时调用它，让重新激活的槽位不会继承前一条连接
// 已逾期的截止时间或结论。
func (s *transportSlot) resetRotation() {
	s.expireAt.Store(0)
	s.connBytes.Store(0)
	s.expiring.Store(false)
	s.degraded.Store(false)
}

// resetConn （重新）初始化新建立连接的轮换状态：生命周期截止时间（含每连接
// 抖动）、承载字节数和 expiring 标记都从零开始。degraded 标记也会被清除：
// 降级是针对前一条连接吞吐量的结论，新拨号的连接应得到干净的状态，直到
// 采样器或探测重新评估它——特别是以 degraded 状态退役、之后又被 grow
// 重新激活的槽位会复用同一个 transportSlot 对象，其新连接不得继承旧的
// 结论。
func (s *transportSlot) resetConn(connLifetime time.Duration) {
	s.resetRotation()
	s.expireAt.Store(time.Now().Add(rotationLifetime(connLifetime)).UnixNano())
}
