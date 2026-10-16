package http2

import (
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/log"
)

// slotConn 标识槽位当前承载的底层连接。net/http 的 http.Transport 没有关闭
// "正在承载活跃流"的连接的 API（CloseIdleConnections 只回收空闲连接），因此
// 传输层自己记录连接身份：DialTLSContext 写入新连接，trackedConn.Close 与
// http2Stream.InvalidateConn 都通过 CAS 清除这个指针——"先比较身份再置空"
// 保证同一时刻只有一个赢家，既不会重复关闭，也不会误杀后来新建的连接。
type slotConn struct {
	c net.Conn
}

// transportSlot 承载一条 HTTP/2 连接（一个通过 MaxConnsPerHost=1 固定到单条
// 连接上的标准库 http.Transport），以及调度器和连接生命周期所作用的状态。
type transportSlot struct {
	// idx 是槽位在调度器预分配数组中的稳定索引，构造时设置一次。
	// retire 会交换删除槽位，因此活跃位置与 idx 会分道扬镳；
	// idx 用于统计上报。
	idx int

	// pool 是槽位当前的 net/http 连接池。MaxConnsPerHost=1 把它固定到一条
	// 连接上，因此"池"与"那条连接"是同一件事；判死换连接就是换掉整个池
	// （见 replacePool），读取一律走 transport()。
	pool atomic.Pointer[http.Transport]
	// newPool 按构造时的参数重建一个池，供 replacePool 使用。只有 newSlot 建出的
	// 槽位有工厂；测试里裸构造的零值槽位没有池可换，判死路径因此跳过重建。
	newPool func() *http.Transport

	active atomic.Int32
	heavy  atomic.Int32 // 活跃 heavy 流数量（>= HeavyStreamThreshold 字节）

	// conn 指向槽位当前的底层连接。只有 DialTLSContext 写入；清除一律走 CAS
	// （trackedConn.Close、http2Stream.InvalidateConn），因此持有一条连接身份的
	// 流可以安全地"只在它仍是当前连接时"关闭它。
	conn atomic.Pointer[slotConn]
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

	// reverify 标记该槽位在进程被挂起（系统睡眠、VM 暂停）期间存活过：底层
	// TCP 连接可能已被中间设备静默丢弃，而 net/http 的空闲回收与 tooIdle
	// 判定都只作用于"没有活跃流"的连接，因此这条连接仍会被当作可用。
	// 标记本身绝不关闭任何连接——时钟离差只是嫌疑，判死由开流前的一次真实
	// 往返给出（见 http2Transport.reverifySlot）。健康循环写入，Open 路径
	// 读取并按"每个槽位每次嫌疑只复核一次"清除。
	reverify atomic.Bool
	// reverifyMu 串行化同一槽位的挂起复核：并发的开流要么等这次复核的结论，
	// 要么（标记已被清掉时）直接放行，因此不会有流在复核进行中溜上那条
	// 尚未验证的连接。它不与调度器锁或槽位内其他锁嵌套。
	reverifyMu sync.Mutex

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
//
// reverify（挂起嫌疑）同样是连接作用域的：它说的是"这条连接可能死在了
// 挂起期间"。连接被换掉之后，下一条连接天然没有嫌疑——无论它是被复核失效、
// 被判死路径关闭，还是重新激活的槽位即将拨号建立——因此在这里一并清除。
func (s *transportSlot) resetRotation() {
	s.expireAt.Store(0)
	s.connBytes.Store(0)
	s.expiring.Store(false)
	s.degraded.Store(false)
	s.reverify.Store(false)
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

// transport 返回槽位当前的连接池。判死会整体替换它（见 replacePool），
// 因此任何使用池的地方都必须通过这个访问器读取，而不是缓存它。
func (s *transportSlot) transport() *http.Transport {
	return s.pool.Load()
}

// replacePool 换上一个全新的连接池，使下一条流必定重新拨号。
//
// 判死只关得掉底层 net.Conn：net/http 的连接池没有"关闭承载活跃流的连接"的
// API，而池里那条 h2 ClientConn 在底层连接关闭之后是否还"可被 ReserveNewRequest
// 选中"，只取决于 h2 客户端栈内部清理的调度时机——readLoop 何时被调度到、
// 下一次写何时失败（写失败要等 cleanupWriteRequest 里的 cc.Close()）、
// 或者 CloseIdleConnections 恰好看到它空闲。这些都不受本层控制，于是
// "判死即换连接"会退化成一次异步收敛：收敛完成之前，下一条流仍可能被交给
// 那条已经死掉的连接（判死重试白费一次尝试，见 TestHTTP2Transport_
// InvalidateConnReplacesPool）。换池把这个保证变回结构性的：新池是空的，
// 下一条流只能拨号。
//
// 旧池原地放弃即可：它最多只有那一条已被关闭的连接，其 h2 栈会自行收敛并
// 退出；这里再调一次 CloseIdleConnections，使旧池在收敛过程中真正空闲下来
// 的连接立即被回收，而不是留到空闲超时。没有池工厂的槽位（测试里的零值）跳过
// 重建——它们本来就没有池。
func (s *transportSlot) replacePool() {
	if s.newPool == nil {
		return
	}
	old := s.pool.Load()
	s.pool.Store(s.newPool())
	if old != nil {
		old.CloseIdleConnections()
	}
}

// invalidateConnFrom 按身份关闭槽位当前承载的底层连接：只有当 sc 仍是槽位的
// "当前连接"时才关闭它（CAS），因此持有一条连接身份的调用方可以安全地
// "只在它仍是当前连接时"关闭它，而不会误杀之后新建的连接。判死路径
// （http2Stream.InvalidateConn）与挂起复核（http2Transport.reverifySlot）
// 共用这条纪律，且它是唯一会关闭承载活跃流的连接的地方。
//
// 判死的同时换掉整个连接池（见 replacePool）：这是"判死即换连接"的结构性
// 保证——池里的 h2 ClientConn 是否还认为这条连接可用取决于 stdlib 内部的
// 清理时机，不能作为调度依据。
//
// 换池先于关闭连接：换池之后读池的开流只能落在新池上拨号，若反过来（先关闭、
// 再换池），并发的开流仍可能在这两行之间从旧池拿到那条刚被关掉的连接——正是
// 本函数要消灭的那个失败（只是窗口窄得多）。先换池把这个窗口彻底关死；随后
// 关闭连接不会碰到新池拨出的连接，因为 sc 是赢家直接持有的旧连接身份。
//
// 返回本次调用是否执行了关闭（即是那个赢家）。连接级事件在这里统一记一条
// Info：默认级别下它是"判死即换连接"唯一可见的锚点，逐流的失败原因与重试
// 决策在代理层记 Debug。
func (s *transportSlot) invalidateConnFrom(sc *slotConn, reason string) bool {
	if sc == nil || !s.conn.CompareAndSwap(sc, nil) {
		return false
	}
	s.resetRotation()
	s.replacePool()
	_ = sc.c.Close()
	log.Info("[TRANSPORT] connection invalidated",
		"slot", s.idx,
		"active_streams", s.active.Load(),
		"reason", reason)
	return true
}
