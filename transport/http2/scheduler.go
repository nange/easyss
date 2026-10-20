package http2

import (
	"math"
	"sync"
	"sync/atomic"

	"github.com/nange/easyss/v3/stats"
)

// 分层压力调度：priority 与 bulk 两个池互相隔离，任一类的突发都不会饿死另一类。
type slotScheduler struct {
	priority *slotPool // 交互式流，基数 = threshold
	bulk     *slotPool // 其他所有流量，基数 = threshold*2

	mu sync.RWMutex // 保护池的扩容/收缩；RLock 保护流的分配
}

type slotPool struct {
	slots     []*transportSlot
	liveCount atomic.Int32
	maxSlots  int
	base      int32 // 该池的压力基数（threshold，bulk 池为 2x）
}

// 每个池从 0 重新编号自己的槽位，因此 idx 只在池内有意义。
func newScheduler(maxSlots int, slots []*transportSlot, threshold int32, prioritySlots int) *slotScheduler {
	pMax := max(min(prioritySlots, maxSlots), 1)
	bMax := maxSlots - pMax
	if bMax < 1 {
		if pMax > 1 {
			pMax = maxSlots - 1
			bMax = 1
		} else {
			// bulk 池保持为空时 poolOf 回退到 priority；强行让 bMax 为 1 会得到 slots 长度为 0 的池，
			// bulk 流越界访问 slots[0]。
			bMax = 0
		}
	}
	for i := 0; i < pMax; i++ {
		slots[i].idx = i
	}
	for i := 0; i < bMax; i++ {
		slots[pMax+i].idx = i
	}
	return &slotScheduler{
		priority: &slotPool{
			slots:    slots[:pMax],
			maxSlots: pMax,
			base:     threshold,
		},
		bulk: &slotPool{
			slots:    slots[pMax:],
			maxSlots: bMax,
			base:     threshold * 2,
		},
	}
}

func (s *slotScheduler) poolOf(highPriority bool) *slotPool {
	if highPriority || s.bulk.maxSlots == 0 {
		return s.priority
	}
	return s.bulk
}

type slotTier int

const (
	tierActive slotTier = iota
	tierExpiring
	tierHeavy
	tierDegraded
	tierRetiring
)

// slotWeight（乘法）与 negativeScore（加法）共用这些权重，两处的严重程度顺序必须一致；
// 权重定得很高，让受损槽位一条流就填满。
const (
	weightHeavy    = 4
	weightExpiring = 8
	weightDegraded = 16
)

func slotTierOf(s *transportSlot) slotTier {
	if s.degraded.Load() && s.expiring.Load() {
		return tierRetiring
	}
	if s.degraded.Load() {
		return tierDegraded
	}
	if s.heavy.Load() > 0 {
		return tierHeavy
	}
	if s.expiring.Load() {
		return tierExpiring
	}
	return tierActive
}

// 次级排序键：加权负载相同时负向状态更少的胜出。
func negativeScore(s *transportSlot) int32 {
	var score int32
	if s.degraded.Load() {
		score += weightDegraded
	}
	if s.heavy.Load() > 0 {
		score += weightHeavy
	}
	if s.expiring.Load() {
		score += weightExpiring
	}
	return score
}

// 负向标记权重的乘积；expiring 高于 heavy 是因为它已到轮换期，应尽快回收。
func slotWeight(s *transportSlot) int32 {
	w := int32(1)
	if s.heavy.Load() > 0 {
		w *= weightHeavy
	}
	if s.expiring.Load() {
		w *= weightExpiring
	}
	if s.degraded.Load() {
		w *= weightDegraded
	}
	return w
}

// 带 expiring/degraded 的空闲槽位按一条流计：没有这个下限它看起来就是空闲的，
// 新流会让疲惫的连接一直存活，饿死轮换/退役。
func weightedActive(s *transportSlot) int32 {
	n := s.active.Load()
	if n == 0 && (s.expiring.Load() || s.degraded.Load()) {
		n = 1
	}
	return n * slotWeight(s)
}

// 已到驱逐期的空闲槽位必须排除在选择之外，否则新流会无限推迟它的轮换/退役。
func draining(s *transportSlot) bool {
	return s.active.Load() == 0 && (s.expiring.Load() || s.degraded.Load())
}

// 先在自己的池里分层搜索，饱和后再看兄弟池：回退槽位只要严格更轻就借用。结果永不为 nil。
func (s *slotScheduler) pick(highPriority bool) *transportSlot {
	pool := s.poolOf(highPriority)
	slot, saturated := pool.tieredSelect()
	if saturated {
		if highPriority {
			stats.RecordPriorityFallback()
		} else {
			stats.RecordBulkFallback()
		}
		// 兄弟池可能为空（maxSlots == 1）：tieredSelect 会越界索引空数组。
		if other := s.otherPool(pool); other.maxSlots > 0 {
			otherSlot, otherSat := other.tieredSelect()
			// 按加权负载比较，空闲的 draining 槽位在借用路径上也不能显得空闲。
			if !otherSat || weightedActive(otherSlot) < weightedActive(slot) {
				return otherSlot
			}
		}
	}
	return slot
}

func (s *slotScheduler) otherPool(pool *slotPool) *slotPool {
	if pool == s.priority {
		return s.bulk
	}
	return s.priority
}

func (p *slotPool) tieredSelect() (*transportSlot, bool) {
	return p.tieredSelectAt(int(p.liveCount.Load()), true)
}

// 不记录调度统计：grow 只问有没有容量。
func (p *slotPool) saturatedIn(live int) bool {
	_, saturated := p.tieredSelectAt(live, false)
	return saturated
}

// 只接受加权负载低于该层容量（见 tierCap）的槽位；draining 槽位在搜索和回退中都被排除。
func (p *slotPool) tieredSelectAt(live int, recordStats bool) (*transportSlot, bool) {
	if live == 0 {
		return p.slots[0], false
	}

	level := p.pressureLevel(live)

	var best *transportSlot
	consider := func(tier slotTier) bool {
		cap := tierCap(tier, level, p.base)
		if cap <= 0 {
			return false
		}
		best = nil
		var bestActive int32 = math.MaxInt32
		var bestNeg int32 = math.MaxInt32
		for i := range live {
			sl := p.slots[i]
			if slotTierOf(sl) != tier || draining(sl) {
				continue
			}
			if weightedActive(sl) >= cap {
				continue
			}
			a := sl.active.Load()
			neg := negativeScore(sl)
			if a < bestActive || (a == bestActive && neg < bestNeg) {
				best, bestActive, bestNeg = sl, a, neg
			}
		}
		return best != nil
	}

	if level == 0 {
		if consider(tierActive) {
			return best, false
		}
		level = 1
	}
	if consider(tierExpiring) {
		if recordStats {
			stats.RecordTierExpiring()
		}
		return best, false
	}
	if consider(tierHeavy) {
		if recordStats {
			stats.RecordTierHeavy()
		}
		return best, false
	}
	if consider(tierDegraded) {
		if recordStats {
			stats.RecordTierDegraded()
		}
		return best, false
	}

	// 分层都满时回退到整体负载最少的槽位，否则所有流会叠到一条拥挤的健康连接上。
	return p.leastActive(live, recordStats), true
}

// level k 表示每个 active 槽位都已达到 2^(k-1)*base 条流，level 0 表示活跃层仍有容量。
func (p *slotPool) pressureLevel(live int) int32 {
	activeMin, hasActive := p.minActiveInTier(live, tierActive)
	if hasActive {
		if activeMin < p.base {
			return 0
		}
		return 1 + floorLog2(activeMin/p.base)
	}
	poolMin := max(p.minActiveInRange(live), p.base)
	return 1 + floorLog2(poolMin/p.base)
}

func floorLog2(v int32) int32 {
	var n int32
	for v > 1 {
		v >>= 1
		n++
	}
	return n
}

// level 0 只有 active 层有容量（= base），level k 的负向层为 2^(k-1)*base。
// 极端级别会溢出 int32，负容量视为无容量。
func tierCap(tier slotTier, level, base int32) int32 {
	if level == 0 {
		if tier == tierActive {
			return base
		}
		return 0
	}
	if tier == tierActive {
		// 级别 >= 1 时不会主动搜索 active 层（按定义全部已达阈值）。
		return 0
	}
	if tier == tierRetiring {
		return 0
	}
	return base << (level - 1)
}

func (p *slotPool) minActiveInTier(live int, tier slotTier) (int32, bool) {
	var min int32 = math.MaxInt32
	found := false
	for i := range live {
		sl := p.slots[i]
		if slotTierOf(sl) != tier {
			continue
		}
		if a := sl.active.Load(); a < min {
			min = a
		}
		found = true
	}
	return min, found
}

func (p *slotPool) minActiveInRange(live int) int32 {
	var min int32 = math.MaxInt32
	for i := range live {
		if a := p.slots[i].active.Load(); a < min {
			min = a
		}
	}
	if min == math.MaxInt32 {
		return 0
	}
	return min
}

// 最终的无上限回退：加权负载最少者胜出，相同时负向标记更少者胜出。retiring/draining
// 只在所有槽位都面临驱逐时作为最后手段返回，使 pick 永不失败。
func (p *slotPool) leastActive(live int, recordStats bool) *transportSlot {
	if live == 0 {
		return p.slots[0]
	}
	var best *transportSlot
	var minWeighted int32 = math.MaxInt32
	var minNeg int32 = math.MaxInt32
	var lastResort *transportSlot
	var resWeighted int32 = math.MaxInt32
	var resNeg int32 = math.MaxInt32
	for i := range live {
		sl := p.slots[i]
		w := weightedActive(sl)
		neg := negativeScore(sl)
		tier := slotTierOf(sl)
		if tier == tierRetiring || draining(sl) {
			if recordStats && tier == tierRetiring {
				stats.RecordTierRetiringSkipped()
			}
			// 负载相同时忙碌槽位胜过 draining 槽位：后者应保持空闲由健康循环驱逐。
			better := w < resWeighted ||
				(w == resWeighted && (neg < resNeg || (neg == resNeg && !draining(sl) && draining(lastResort))))
			if better {
				lastResort, resWeighted, resNeg = sl, w, neg
			}
			continue
		}
		if w > minWeighted || (w == minWeighted && neg >= minNeg) {
			continue
		}
		best, minWeighted, minNeg = sl, w, neg
	}
	if best == nil {
		return lastResort
	}
	return best
}

// 决策与 liveCount 更新必须在同一个临界区内完成，否则并发扩容者会过度扩容。
func (s *slotScheduler) grow(highPriority bool) (*slotPool, int32) {
	pool := s.poolOf(highPriority)
	target, _ := s.growTarget(pool)
	if target == nil {
		return nil, 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 获取锁后再次检查：等待期间另一个扩容者可能已激活槽位或改变了分层。
	target, live := s.growTarget(pool)
	if target == nil {
		return nil, 0
	}
	// shrink/retire 交换删除时不清标记，重新激活的槽位会带着上一条连接的 expiring/degraded
	// 与逾期截止时间，激活前必须清零。
	if live == 0 && target.maxSlots >= 2 {
		target.slots[live].resetRotation()
		target.slots[live+1].resetRotation()
		target.liveCount.Add(2)
		return target, 2
	}
	target.slots[live].resetRotation()
	target.liveCount.Add(1)
	return target, live + 1
}

// 所属池未满且分层饱和才扩它，满了才考虑兄弟池，且兄弟池也必须分层饱和，
// 否则一个池的持续饱和会逐条流撑大另一个池。
func (s *slotScheduler) growTarget(pool *slotPool) (*slotPool, int32) {
	live := pool.liveCount.Load()
	if int(live) < pool.maxSlots {
		if live == 0 || pool.saturatedIn(int(live)) {
			return pool, live
		}
		return nil, 0
	}
	// 所属池已达上限时，只有它同样分层饱和才去动兄弟池。
	if live > 0 && !pool.saturatedIn(int(live)) {
		return nil, 0
	}
	other := s.otherPool(pool)
	live = other.liveCount.Load()
	if int(live) < other.maxSlots && (live == 0 || other.saturatedIn(int(live))) {
		return other, live
	}
	return nil, 0
}

// 退役两个池的所有空闲槽位；调用方必须持有 s.mu。
func (s *slotScheduler) shrinkIdleLocked() {
	for _, pool := range []*slotPool{s.priority, s.bulk} {
		for pool.removeIdleLocked() {
		}
	}
}

func (p *slotPool) removeIdleLocked() bool {
	live := int(p.liveCount.Load())
	for i := range live {
		if p.slots[i].active.Load() != 0 {
			continue
		}
		p.removeAtLocked(i, live)
		return true
	}
	return false
}

// 交换删除位置 i 的槽位；调用方必须持有 s.mu。
func (p *slotPool) removeAtLocked(i, live int) {
	last := live - 1
	if i != last {
		p.slots[i], p.slots[last] = p.slots[last], p.slots[i]
	}
	p.liveCount.Add(-1)
}

// 流数必须在锁内重新检查，否则并发的 Open 会把新流放到正在被移除的槽位上。
func (s *slotScheduler) remove(sl *transportSlot) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sl.active.Load() != 0 {
		return false
	}
	for _, pool := range []*slotPool{s.priority, s.bulk} {
		live := int(pool.liveCount.Load())
		for i := range live {
			if pool.slots[i] != sl {
				continue
			}
			pool.removeAtLocked(i, live)
			return true
		}
	}
	return false
}
