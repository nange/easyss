package http2

import (
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/log"
)

// slotConn 标识一条底层连接。net/http 的 http.Transport 没有关闭"正在承载活跃流"
// 的连接的 API（CloseIdleConnections 只回收空闲连接），因此传输层自己记录连接
// 身份：DialTLSContext 写入新连接，trackedConn.Close 与 invalidateConn 都
// 通过 CAS 认领/清除这个指针——"先比较身份再置空"保证同一时刻只有一个赢家，既不会
// 重复关闭，也不会误杀后来新建的连接。
type slotConn struct {
	c net.Conn
}

// slotTransport 是槽位连接池的一"代"：一个把 MaxConnsPerHost 固定为 1 的
// net/http 连接池，以及由这张池的拨号路径建立的那一条连接。
//
// 不变量：一"代"最多只有一条连接，而且这条连接一旦关闭（无论 net/http 回收还是
// 本层判死），这一代立即作废——`retireGeneration` 把槽位换到新一代，旧一代的
// conn 指针从此为空。于是"代"本身就是完整的连接身份：流在提交请求时记下当前这
// 一代（http2Stream.gen），就等于记下了自己实际用过的那条连接，不需要再在写
// 路径上"快照"槽位的当前连接。判死（invalidateConn）与判活（ConnAlive）都只在
// 自己那一代里进行，一条正在死去的流永远碰不到后来新建的连接——判死换池
// （#226）之后仍然存在的"把新连接记成自己身份、之后误杀健康连接"的窗口因此
// 在结构上不存在。
//
// 唯一已知的例外来自 net/http 自己：一条连接达到服务端通告的
// maxConcurrentStreams 时，h2 栈会把请求报成 ErrNoCachedConn，外层 transport
// 丢掉那条 persistConn、connsPerHost 减一，然后在同一张池里再拨一条——此时
// 一张池里短暂地有两条连接，"代 == 连接"不再成立。触发它需要单条连接上
// ≥ maxConcurrentStreams（Go 默认 250）条并发流，而调度器按 least-active 把流
// 摊到多个槽位，实际要几百上千条并发流；同一个前提也是"一个槽位一条连接"这个
// 模型本身的前提。
type slotTransport struct {
	// slot 是这一代所属的槽位：连接关闭时要通过它把槽位换到新一代
	// （见 retireGeneration）。
	slot *transportSlot
	// tr 是这一代的连接池。使用方必须持有这一代本身，而不是反复读槽位的
	// "当前一代"：只有这样"连接身份"与"提交请求用的池"才必然同源。
	tr *http.Transport
	// conn 是这一代拨号路径建立的连接（不变量：一代至多一条）。只有这一代的
	// DialTLSContext 写入；清除一律走 takeConn 的 CAS。
	conn atomic.Pointer[slotConn]
}

// transportSlot 承载一条 HTTP/2 连接（一个通过 MaxConnsPerHost=1 固定到单条
// 连接上的标准库 http.Transport），以及调度器和连接生命周期所作用的状态。
type transportSlot struct {
	// idx 是槽位在调度器预分配数组中的稳定索引，构造时设置一次。
	// retire 会交换删除槽位，因此活跃位置与 idx 会分道扬镳；
	// idx 用于统计上报。
	idx int

	// gen 是槽位当前的连接池"代"（池 + 该池建立的唯一一条连接，见
	// slotTransport）。判死与连接回收都会把槽位换到新一代（advanceGeneration），
	// 读取一律走 generation()/transport()。
	gen atomic.Pointer[slotTransport]
	// newGen 按构造时的参数重建一代，供 advanceGeneration 使用。只有 newSlot
	// 建出的槽位有工厂；测试里裸构造的零值槽位没有池可换，换代路径因此跳过。
	newGen func() *slotTransport

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

// generation 返回槽位当前的连接池"代"。"本流用的是哪条连接"由流提交时记下的
// 那一代回答（见 slotTransport），因此需要连接身份的地方必须持有那一代，
// 而不是每次重新读这里。
func (s *transportSlot) generation() *slotTransport {
	return s.gen.Load()
}

// transport 返回槽位当前一代的连接池。换代（判死、连接回收）会整体替换它，
// 因此任何使用池的地方都必须通过这个访问器读取，而不是缓存它。
func (s *transportSlot) transport() *http.Transport {
	if gen := s.gen.Load(); gen != nil {
		return gen.tr
	}
	return nil
}

// connIdentity 返回槽位当前一代承载的连接身份（这一代还没有连接时为 nil）。
// 健康循环用它判断"这个槽位是否有连接需要复核"；判死与判活必须持有自己那一代
// （见 slotTransport），而不是这里的"当前"值。
func (s *transportSlot) connIdentity() *slotConn {
	if gen := s.gen.Load(); gen != nil {
		return gen.conn.Load()
	}
	return nil
}

// advanceGeneration 把当前一代换成一代全新的空池：下一条 Open 只能拨号。
//
// 只换"池 + 连接身份"，连接本身由调用方处理（判死要关闭它，自然回收时它已经
// 关闭）。只有 gen 仍是当前一代时才换：槽位已经换代时，当前池属于更新的一代
// （甚至已经拨出了健康连接），绝不能把它顶掉。没有池工厂的槽位（测试里的裸
// 构造）跳过重建——它们本来就没有池。
//
// 为什么判死必须换代：判死只关得掉底层 net.Conn，而 net/http 的连接池没有
// "关闭承载活跃流的连接"的 API，那条 h2 ClientConn 在底层连接关闭之后是否还
// "可被 ReserveNewRequest 选中"，只取决于 h2 客户端栈内部清理的调度时机——
// readLoop 何时被调度到、下一次写何时失败（要等 cleanupWriteRequest 里的
// cc.Close()）、或者 CloseIdleConnections 恰好看到它空闲。这些都不受本层控制，
// 于是"判死即换连接"会退化成一次异步收敛：收敛完成之前，下一条流仍可能被交给
// 那条已经死掉的连接（判死重试白费一次尝试，见 TestHTTP2Transport_
// InvalidateConnReplacesPool）。换代把这个保证变回结构性的：新池是空的，
// 下一条流只能拨号。
//
// 旧池原地放弃即可：它最多只有那一条已被关闭的连接，其 h2 栈会自行收敛并
// 退出；判死路径还会对旧池补一次 CloseIdleConnections，使它在收敛过程中真正
// 空闲下来的连接立即被回收，而不是留到空闲超时。
func (s *transportSlot) advanceGeneration(gen *slotTransport) bool {
	if s.newGen == nil || gen == nil {
		return false
	}
	return s.gen.CompareAndSwap(gen, s.newGen())
}

// takeConn 认领一代的连接身份：赢下 gen.conn 的 CAS 之后，返回值从此为空，并且
// 只有这个赢家有权关闭它、让这一代作废。expect 非 nil 时要求"它仍是这条连接"
// （trackedConn 关闭自己那条连接）；为 nil 时认领这一代当前的连接（判死路径：
// 身份就是这一代本身，见 slotTransport 的不变量）。
//
// 返回 nil 表示这一代已经没有连接了（已关闭、已作废，或从未拨号），调用方应当
// 把它当作无操作。
func (s *transportSlot) takeConn(gen *slotTransport, expect *slotConn) *slotConn {
	if gen == nil {
		return nil
	}
	if expect == nil {
		expect = gen.conn.Load()
		if expect == nil {
			return nil
		}
	}
	if !gen.conn.CompareAndSwap(expect, nil) {
		return nil
	}
	return expect
}

// retireGeneration 让一代作废：它的连接已经关闭（net/http 回收连接时经
// trackedConn.Close 调用），这一代不能再承载任何新流。槽位换到新一代之后，
// 持有旧一代的流读到的 gen.conn 是空的——它们本来就绑在已关闭的连接上，判死
// 路径对它们自然是无操作。
//
// 这是"代 == 连接"不变量的执行点。只有赢得连接身份 CAS 的调用者会执行，因此
// 同一条连接不会作废两代；它只清掉自己那一代的连接指针，碰不到新池。
// 连接作用域的状态（轮换截止时间/字节数/降级/嫌疑）不在这里清理：连接是自然
// 结束的，下一次拨号的 resetConn 会从零开始。
func (s *transportSlot) retireGeneration(gen *slotTransport, conn *slotConn) {
	if s.takeConn(gen, conn) != nil {
		s.advanceGeneration(gen)
	}
}

// invalidateConn 判死一代承载的连接：按身份关闭它（takeConn 的 CAS 决定唯一
// 赢家），并把槽位换到新一代，使下一次 Open 必定拨号。判死路径
// （http2Stream.InvalidateConn）与挂起复核（http2Transport.reverifySlot）共用
// 这条纪律，且它是唯一会关闭承载活跃流的连接的地方。
//
// 身份就是调用方持有的那一代（见 slotTransport）：旧一代的流连新一代连接的身份
// 都拿不到，因此这条路径同时挡住了"同一条连接被多条流重复失效"（只有赢家执行）
// 与"误杀后来新建的连接"（换代之后的判死是无操作）。判死与自然回收的区别只在
// 收尾：判死是"这条连接坏了"，连接作用域的轮换/降级/嫌疑状态一并清零。
//
// 换代先于关闭连接：换代之后读池的开流只能落在新池上拨号，若反过来（先关闭、
// 再换代），并发的开流仍可能在这两行之间从旧池拿到那条刚被关掉的连接——正是
// 本函数要消灭的那个失败（只是窗口窄得多）。先换代把这个窗口彻底关死；随后
// 关闭连接不会碰到新池拨出的连接，因为 sc 是赢家直接持有的旧一代的连接。
//
// 返回本次调用是否执行了关闭（即是那个赢家）。连接级事件在这里统一记一条
// Info：默认级别下它是"判死即换连接"唯一可见的锚点，逐流的失败原因与重试
// 决策在代理层记 Debug。
func (s *transportSlot) invalidateConn(gen *slotTransport, reason string) bool {
	sc := s.takeConn(gen, nil)
	if sc == nil {
		return false
	}
	// 只有这一代仍是当前一代时才清连接作用域状态并换代：判死的对象是"这条连接
	// 所属的那一代"，若它已经是旧的一代，当前池属于更新的一代（甚至已经拨出了
	// 健康连接），绝不能连带抛弃它，也不能清掉它的轮换/嫌疑状态。
	//
	// 赢下上面那次 CAS 之后这个判断是稳定的：换代只能由"赢下当前一代的 conn
	// CAS"触发，而那一代的 conn 已经被本调用置空，其他调用者不可能再赢一次。
	if s.gen.Load() == gen {
		s.resetRotation()
		if s.advanceGeneration(gen) {
			// 旧池原样放弃之前补一次空闲回收：它在收敛过程中真正空闲下来的连接
			// 立即释放，而不是留到空闲超时。这件事不能放进 advanceGeneration：
			// 自然回收（trackedConn.Close）那条路径可能正跑在 h2 的空闲回收里，
			// 对同一张池重入 CloseIdleConnections 会重复加同一把锁。
			gen.tr.CloseIdleConnections()
		}
	}
	_ = sc.c.Close()
	log.Info("[TRANSPORT] connection invalidated",
		"slot", s.idx,
		"active_streams", s.active.Load(),
		"reason", reason)
	return true
}
