package http2

import (
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/log"
)

// slotConn 是底层连接的身份，用于 CAS 认领，保证只有赢家关闭它。
type slotConn struct {
	c net.Conn
}

// slotTransport 是连接池的一"代"：一个 net/http 池加它拨出的连接。通常一代一条连接、
// 连接一关即换代；但同代内可能重拨并顶替身份（见 docs/architecture.md 的例外），所以代
// 不单独等于连接身份，流要自己记 GotConn 回报的那一条。
type slotTransport struct {
	slot *transportSlot
	// 使用方必须持有这一代本身，而不是反复读槽位当前一代。
	tr *http.Transport
	// 只由本代 DialTLSContext 写入，清除走 takeConn 的 CAS。
	conn atomic.Pointer[slotConn]
}

// transportSlot 承载一条 HTTP/2 连接，以及调度与连接生命周期所作用的状态。
type transportSlot struct {
	// 预分配数组中的稳定索引，仅用于统计上报。
	idx int

	// 当前一代连接池，读取一律走 generation()/transport()。
	gen atomic.Pointer[slotTransport]
	// 按构造参数重建一代，供 advanceGeneration 使用；为零表示没有池可换。
	newGen func() *slotTransport

	active atomic.Int32
	heavy  atomic.Int32 // 活跃 heavy 流数量

	// 连接进入空闲（active==0）的墙钟时刻（unix 纳秒；0 表示有活跃流或尚未登记）。
	// h2 的 tooIdle 同样按墙钟判断，睡眠跳变会让空闲连接立刻越过空闲阈值。
	idleSince atomic.Int64

	// 所有流累计下载字节数，健康循环采样它估算近期吞吐量。
	bytesRecv atomic.Int64
	degraded  atomic.Bool

	expireAt  atomic.Int64 // 当前连接的 unix 纳秒截止时间
	connBytes atomic.Int64 // 当前连接在任一方向承载的字节数
	expiring  atomic.Bool

	// 该槽位经历过挂起，底层连接可能已被静默丢弃。标记绝不关闭连接：判死由开流前的一次
	// 真实往返给出（http2Transport.reverifySlot），误判有代价。
	reverify atomic.Bool
	// 串行化挂起复核，避免流在复核进行中溜上尚未验证的连接。
	reverifyMu sync.Mutex

	// 以下状态仅由健康循环 goroutine 访问。
	lastBytes     int64
	lastHeavy     int // 跟踪 heavy 0->1 的转换
	lowCycles     int
	recoverCycles int

	suspected      bool
	probeLowCycles int
	lastProbeAt    time.Time
	// 探测判定该槽位无责后的静默截止时间，以及连续 inconclusive 的次数（退避用）。
	probeHoldUntil time.Time
	probeBackoff   int
	// 上述探测状态所属的连接身份。换代后通常立刻重拨，健康周期看不到"这一代无连接"的
	// 窗口，只能靠身份比对作废旧连接上的结论。
	probeConn *slotConn
}

// resetRotation 把连接作用域的状态清回"无连接"基线。expireAt 必须清零而不是设新截止时间：
// rotationDue 只在 expireAt > 0 时触发，否则每个周期都会重复轮换。
func (s *transportSlot) resetRotation() {
	s.expireAt.Store(0)
	s.connBytes.Store(0)
	s.expiring.Store(false)
	s.degraded.Store(false)
	s.reverify.Store(false)
}

// resetConn 初始化新连接的截止时间（含抖动），并清掉前一条连接的轮换与降级结论。
func (s *transportSlot) resetConn(connLifetime time.Duration) {
	s.resetRotation()
	s.expireAt.Store(time.Now().Add(rotationLifetime(connLifetime)).UnixNano())
	s.idleSince.Store(time.Now().UnixNano())
}

// idleFor 返回当前连接已空闲的墙钟时长；0 表示有活跃流或尚未登记连接。用墙钟而不是单调钟：
// h2 的 tooIdle 就是这样计算的，睡眠期间的墙钟跳变必须体现在这里。
func (s *transportSlot) idleFor(now time.Time) time.Duration {
	since := s.idleSince.Load()
	if since == 0 {
		return 0
	}
	return now.Sub(time.Unix(0, since))
}

// generation 返回槽位当前的连接池"代"。
func (s *transportSlot) generation() *slotTransport {
	return s.gen.Load()
}

// transport 返回当前一代的连接池；换代是整体替换，因此每次都要读，不能缓存。
func (s *transportSlot) transport() *http.Transport {
	if gen := s.gen.Load(); gen != nil {
		return gen.tr
	}
	return nil
}

// connIdentity 返回当前一代的连接身份（无连接时为 nil）。
func (s *transportSlot) connIdentity() *slotConn {
	if gen := s.gen.Load(); gen != nil {
		return gen.conn.Load()
	}
	return nil
}

// advanceGeneration 把当前一代换成全新的空池，使下一条 Open 只能拨号。判死只关得掉底层
// net.Conn，h2 ClientConn 何时被移出池取决于标准库内部调度。
func (s *transportSlot) advanceGeneration(gen *slotTransport) bool {
	if s.newGen == nil || gen == nil {
		return false
	}
	return s.gen.CompareAndSwap(gen, s.newGen())
}

// takeConn 认领一代的连接身份：赢下 CAS 之后只有赢家有权关闭它。expect 为 nil 时认领该代
// 当前连接；返回 nil 表示这一代已无连接。
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

// retireGeneration 让一代作废：它的连接正在关闭（net/http 回收时经 trackedConn.Close 调用，
// 换代先于实际关闭，使 close_notify 阻塞期间迟到的拨号看不到旧身份）。只有赢得连接身份 CAS
// 的调用者会执行，因此同一条连接不会作废两代。
func (s *transportSlot) retireGeneration(gen *slotTransport, conn *slotConn) {
	if s.takeConn(gen, conn) != nil {
		s.advanceGeneration(gen)
	}
}

// invalidateConnIf 只在这一代仍持有 expect 时失效：身份已被替换（net/http 同池重拨）时
// 什么都不关。判死方必须传自己实际用过的那条连接——按"这一代的当前身份"关，会把对方刚
// 拨出来、还没参与判定的好连接一起关掉。换代先于关闭，否则并发的开流会拿到刚关掉的连接。
func (s *transportSlot) invalidateConnIf(gen *slotTransport, expect *slotConn, reason string) bool {
	// 认领当前身份只留给 retireIdleConn（它直接走 retireConn）：判死必须有确切身份。
	if expect == nil {
		return false
	}
	sc, ok := s.retireConn(gen, expect)
	if !ok {
		return false
	}
	_ = sc.c.Close()
	log.Info("[TRANSPORT] connection invalidated",
		"slot", s.idx,
		"active_streams", s.active.Load(),
		"reason", reason)
	return true
}

// retireIdleConn 退役一条已不可能再被复用的空闲连接：摘身份、换代，但不硬关底层连接。
// 扫掠与 Open 的 active+1 之间没有互斥，硬关会打断一条刚起步、尚未在 h2 登记的流；
// CloseIdleConnections 只关真正空闲的连接，其余的由 h2 在自己的空闲超时后关闭。
func (s *transportSlot) retireIdleConn(gen *slotTransport, reason string) bool {
	if _, ok := s.retireConn(gen, nil); !ok {
		return false
	}
	log.Info("[TRANSPORT] idle connection retired",
		"slot", s.idx,
		"active_streams", s.active.Load(),
		"reason", reason)
	return true
}

// retireConn 认领这一代的连接身份并换到新一代，返回赢得 CAS 的连接。expect 非 nil 时只在
// 身份仍是它时才认领。只关池里的空闲连接：是否硬关底层连接由调用方按判死结论决定。
func (s *transportSlot) retireConn(gen *slotTransport, expect *slotConn) (*slotConn, bool) {
	sc := s.takeConn(gen, expect)
	if sc == nil {
		return nil, false
	}
	// 只有这一代仍是当前一代时才清状态并换代：否则当前池属于更新的一代，不能连带抛弃它。
	if s.gen.Load() == gen {
		s.resetRotation()
		if s.advanceGeneration(gen) {
			// 不能放进 advanceGeneration：trackedConn.Close 那条路径可能正跑在 h2 的
			// 空闲回收里，对同一张池重入 CloseIdleConnections 会重复加同一把锁。
			gen.tr.CloseIdleConnections()
		}
	}
	return sc, true
}
