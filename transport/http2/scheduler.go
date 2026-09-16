package http2

import (
	"math"
	"sync"
	"sync/atomic"

	"github.com/nange/easyss/v3/stats"
)

// slotScheduler 用优先级感知的分层压力调度器把新流映射到槽位上，并管理活跃
// 槽位集合：负载下扩容、空闲时收缩、退役槽位的交换删除。槽位健康状态本身
// 由 slotLifecycle 负责；调度器只参考这些标记（heavy/degraded/expiring）
// 来判断槽位是否还能接收新流。
//
// 调度模型——两个隔离的池 × 健康分层：
//
//   - 流按优先级分类，每个类别拥有专属的槽位池，因此 DNS 查询或下载（bulk）
//     激活自己的连接而不是共享交互式连接，且任一类的突发流量永远不会饿死
//     另一类：
//
//     priority 池：交互式目的地（见 stream.go），压力基数 = threshold，
//     至多 PrioritySlotRatio×maxSlots 条连接；
//     bulk 池：其他所有流量，压力基数 = bulkThreshold（2×threshold），
//     至多 (1-ratio)×maxSlots 条连接。
//
//   - 池内槽位按健康分层排序（见 slotTierOf）：active（健康）槽位优先承载
//     新流。一旦所有 active 槽位都达到池的压力基数，expiring 槽位接替，
//     然后是 heavy 槽位，最后才是 degraded 槽位（最差候选，最后的出路）。
//     负向分层按加权负载比较——活跃流数乘以槽位负向标记的复合权重
//     （heavy ×4、expiring ×8、degraded ×16，见 slotWeight），因此 heavy
//     槽位上 1 条流的重量相当于 4 条健康流，expiring 槽位上 1 条相当于 8，
//     degraded 槽位上 1 条相当于 16，而 heavy+expiring+degraded 槽位
//     复合到 ×512。带有 expiring 或 degraded 标记的空闲槽位（active == 0）
//     仍按标记权重计重——绝不是 0，见 weightedActive：它不能看起来是空闲的，
//     否则新流会让疲惫的连接一直存活、推迟其驱逐。槽位只有在加权负载达到
//     分层容量后才算满，而该容量每当活跃层被推高到基数的下一个 2 的幂倍数
//     时翻倍——因此完全饱和的池会持续分散负载，而不是堆到一条连接上。即将
//     被驱逐的槽位完全不会被选中：同时带 degraded 和 expiring 标记的槽位
//     归为 tierRetiring，带 expiring 或 degraded 标记的空闲槽位处于 draining
//     （见 draining）——新流不得让这两类槽位继续存活，它们会排空到空闲，
//     由健康循环轮换/退役，并被新连接取代。
//
//   - 扩容优先选择新连接而不是压榨负向槽位：当池的分层饱和时它扩容自己的池，
//     一旦池达到连接上限则改扩兄弟池（兄弟池也必须分层饱和；否则 pick 直接
//     借用它的健康槽位）。只有当两个池都到上限且每个分层都饱和时，流才会
//     堆到负载最少的槽位上。
type slotScheduler struct {
	priority *slotPool // 交互式流，基数 = threshold
	bulk     *slotPool // 其他所有流量，基数 = threshold*2

	mu sync.RWMutex // 保护池的扩容/收缩；RLock 保护流的分配
}

// slotPool 是某一类的专属槽位集合。槽位预分配并初始化为 maxSlots；
// liveCount 在首次使用（+2）和负载下懒增长，槽位空闲时收缩。
type slotPool struct {
	slots     []*transportSlot
	liveCount atomic.Int32 // 当前活跃槽位数（0..maxSlots）
	maxSlots  int
	base      int32 // 该池的压力基数（threshold，bulk 池为 2x）
}

// newScheduler 把预分配的槽位数组拆分为 priority 池（前 prioritySlots 个条目）
// 和 bulk 池（其余部分），保持总连接上限不变。拆分通过 prioritySlots 体现
// PrioritySlotRatio；只要 maxSlots >= 2，两个池各至少得到一个槽位。
// 每个池都从 0 重新编号自己的槽位，因此槽位的稳定 idx 只在自己池内有意义。
func newScheduler(maxSlots int, slots []*transportSlot, threshold int32, prioritySlots int) *slotScheduler {
	pMax := max(min(prioritySlots, maxSlots), 1)
	bMax := maxSlots - pMax
	if bMax < 1 {
		if pMax > 1 {
			// 退化拆分（ratio 为 1 或 prioritySlots >= maxSlots）：把末尾
			// 槽位给 bulk 池。
			pMax = maxSlots - 1
			bMax = 1
		} else {
			// maxSlots == 1：bulk 池保持为空（maxSlots 为 0），poolOf 回退到
			// priority 池。这里若强制 bMax 为 1，就会得到 maxSlots 为 1 但
			// 长度为 0 的 bulk.slots 切片，任何 bulk 流都会越界访问 slots[0]。
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

// poolOf 返回给定类别流所属的池。当 bulk 池为空（退化拆分）时，bulk 流
// 共享 priority 池，此时行为如同单池模型。
func (s *slotScheduler) poolOf(highPriority bool) *slotPool {
	if highPriority || s.bulk.maxSlots == 0 {
		return s.priority
	}
	return s.bulk
}

// slotTier 按槽位最负面的健康信号对其分类。分层从好到差排序：一个槽位恰好
// 属于一个分层，tieredSelect 按此顺序遍历：
//
//	tierActive    — 无标记：连接健康且优先；
//	tierExpiring  — 轮换已逾期，但连接很可能仍然可用：把新流路由到它上面，
//	                让连接撑到流间隙，分散同批重拨而不是聚成一簇；
//	                一旦空闲，槽位进入 draining 并被排除在选择之外，
//	                以便完成轮换；
//	tierHeavy     — heavy 流独占 TCP 窗口，拖累任何共享流（丢包时队头阻塞），
//	                但连接本身是健康的；
//	tierDegraded  — 连接被证实持续低吞吐，最差候选，仅作最后手段；
//	tierRetiring  — degraded 且 expiring：轮换已逾期且被证实缓慢，
//	                没有恢复价值（即使快速流也无法挽回逾期的轮换）。
//	                永远不会被选中：槽位排空到空闲，由健康循环退役，
//	                并被新连接取代。
type slotTier int

const (
	tierActive slotTier = iota
	tierExpiring
	tierHeavy
	tierDegraded
	tierRetiring
)

// 负向标记的负载权重，由 slotWeight（乘法）和 negativeScore（加法）共用，
// 因此严重程度顺序始终保持一致：degraded 16 > expiring 8 > heavy 4。
// expiring 连接比单纯 heavy 更糟——它已到轮换期、应尽快回收——因此其权重
// 高于 heavy；degraded 高于两者，使持续慢速的连接先被排空并退役。
// 权重刻意定得很高：每个负向标记把其分层的流容量减半（tierCap / weight），
// 因此 expiring 和 degraded 槽位只需一条流就会填满，并迅速排空走向
// 轮换/退役。
const (
	weightHeavy    = 4
	weightExpiring = 8
	weightDegraded = 16
)

// slotTierOf 返回槽位当前所属的分层。heavy+expiring 槽位归为 heavy
// （较重的标记胜出），任何含 degraded 的组合归为 degraded——唯一例外是
// 同时 degraded 和 expiring 的槽位归为 tierRetiring：它轮换已逾期且被
// 证实缓慢，因此调度器永远不会选中它（见 leastActive），健康循环在它
// 空闲后将其退役。
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

// negativeScore 量化槽位带有的负向标记数量，用作分层内的次级排序键以及
// 无上限回退中的排序依据：负载相同的槽位中，负向状态更少的胜出。
// 分值使用共享的负向标记权重（weightDegraded > weightExpiring >
// weightHeavy），因此严重程度顺序始终与 slotWeight 一致。
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

// slotWeight 返回槽位负向标记的负载权重，即共享负向标记权重
// （weightHeavy、weightExpiring、weightDegraded；无标记时为 1）的乘积。
// heavy+expiring 槽位上的一条流重量为 weightHeavy×weightExpiring = 32 倍
// 健康流，heavy+expiring+degraded 槽位上为 4×8×16 = 512 倍——多个负向
// 状态复合，因此槽位只有在加权负载达到池的阈值后才算满。expiring 的权重
// 刻意设高（8，高于 heavy 的 4）：槽位已到轮换期，流应避开它，让它空闲
// 并被快速回收；degraded 更高（16），使慢连接只需一条流即达容量、
// 快速排空走向退役。expiring/degraded 标记的空闲下限由 weightedActive
// 应用。
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

// weightedActive 返回槽位的加权负载：活跃流数乘以所有负向标记的复合权重。
// 带有 expiring 或 degraded 标记的空闲槽位（active == 0）按一条流计，
// 因此按标记权重计重（expiring 8、degraded 16、两者都有 128）而不是 0：
// 没有这个下限它看起来就是空闲的，新流会堆上去，使疲惫的连接一直存活，
// 饿死健康循环的轮换/退役。heavy 不需要下限：heavy > 0 意味着至少有一条
// 活跃的 heavy 流（标记在关闭时每条流恰好释放一次），因此带 heavy 标记的
// 槽位永远不会空闲。
func weightedActive(s *transportSlot) int32 {
	n := s.active.Load()
	if n == 0 && (s.expiring.Load() || s.degraded.Load()) {
		n = 1
	}
	return n * slotWeight(s)
}

// draining 报告槽位是否空闲（active == 0）且带有 expiring 或 degraded 标记。
// 这样的槽位已到驱逐期——轮换或退役——不能被新流重新激活：调度器像对待
// retiring 槽位一样把它排除在选择之外，因此它保持空闲直到健康循环关闭
// 连接。当所有活跃槽位都是负向时，draining 槽位仍可作为绝对的最后手段使用。
func draining(s *transportSlot) bool {
	return s.active.Load() == 0 && (s.expiring.Load() || s.degraded.Load())
}

// pick 返回新流应使用的槽位：流的类别选择自己的池，用分层压力调度器搜索。
// 当池的每个分层都饱和（且池达到连接上限）时，会再搜索一次另一个池——
// 在堆到饱和连接上之前先借用它的健康槽位。即使另一个池也饱和了，它的
// 回退槽位也可能比我们的负载低得多（例如 2 条流的 heavy 槽位 vs 我们堆了
// 10 条流的健康槽位），因此只要它严格更轻就会借用。结果永远不会为 nil：
// 没有活跃槽位时返回第一个预分配的槽位。
func (s *slotScheduler) pick(highPriority bool) *transportSlot {
	pool := s.poolOf(highPriority)
	slot, saturated := pool.tieredSelect()
	if saturated {
		// 池已完全饱和：在采用无上限回退之前，先给另一个池一次机会。
		if highPriority {
			stats.RecordPriorityFallback()
		} else {
			stats.RecordBulkFallback()
		}
		// 兄弟池可能为空（退化拆分，maxSlots == 1）：它不拥有任何槽位，
		// 无从借用，tieredSelect 会越界索引它的空槽位数组。
		if other := s.otherPool(pool); other.maxSlots > 0 {
			otherSlot, otherSat := other.tieredSelect()
			// 只有当兄弟池的回退槽位严格更轻时才借用，按加权负载比较，
			// 使负向标记的代价保持一致（空闲的 draining 槽位在借用路径上
			// 也不能看起来是空闲的）。
			if !otherSat || weightedActive(otherSlot) < weightedActive(slot) {
				return otherSlot
			}
		}
	}
	return slot
}

// otherPool 返回给定池的兄弟池。
func (s *slotScheduler) otherPool(pool *slotPool) *slotPool {
	if pool == s.priority {
		return s.bulk
	}
	return s.priority
}

// tieredSelect 在压力调度器下为一条新流挑选池内最佳槽位，返回 (slot, saturated)。
// 当没有任何分层还有容量时 saturated 为 true，此时 slot 是回退结果
// （见下文）。搜索本身见 tieredSelectAt。
func (p *slotPool) tieredSelect() (*transportSlot, bool) {
	return p.tieredSelectAt(int(p.liveCount.Load()), true)
}

// saturatedIn 报告分层调度器在池内是否已无容量——即 tieredSelect 将走无上限
// 回退路径。grow 用它判断何时真正需要新连接；与 tieredSelect 不同，它不记录
// 分层调度统计。
func (p *slotPool) saturatedIn(live int) bool {
	_, saturated := p.tieredSelectAt(live, false)
	return saturated
}

// tieredSelectAt 是对前 `live` 个槽位的分层搜索：
//
// 搜索按可取性顺序遍历分层——先是 active，然后 expiring、heavy 和
// degraded——层内优先选择活跃流最少的槽位，平局时用 negativeScore 打破。
// 分层只接受加权负载（active × 负向标记复合权重，空闲负向槽位以标记权重
// 为下限，见 weightedActive）低于该分层容量的槽位，容量随压力级别缩放
// （见 pressureLevel 和 tierCap）。一旦所有分层都满，回退把流堆到整体
// 负载最少的槽位上（按加权负载，无上限）：堆在那里可以保持负载均衡，
// 而不是把所有流叠到一条拥挤的健康连接上。即将被驱逐的槽位被排除在所有
// 搜索和回退之外：同时 degraded 和 expiring 的槽位（tierRetiring）以及
// 带 expiring 或 degraded 标记的空闲槽位（draining，见 draining）——
// 新流绝不能使它们存活，它们会排空到空闲，由健康循环轮换/退役。
func (p *slotPool) tieredSelectAt(live int, recordStats bool) (*transportSlot, bool) {
	if live == 0 {
		return p.slots[0], false
	}

	level := p.pressureLevel(live)

	// consider 在当前容量内挑选某一分层中活跃最少、负向最少的槽位；
	// 它报告这样的槽位是否存在。容量按加权负载比较（active × 槽位负向标记
	// 的复合权重，空闲负向槽位以标记权重为下限），因此当池阈值为 8 时，
	// 有 1 条流且带一个 heavy 标记（权重 4）的槽位仍然开放——只有当每个
	// 候选槽位的加权负载都达到阈值，池才会扩容。draining 槽位（带
	// expiring/degraded 标记的空闲槽位）被完全跳过：重新激活它们会推迟其
	// 轮换/退役。
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
		// 活跃层低于基数时只有 active 分层有容量：优先健康槽位，
		// 负向槽位不予考虑。
		if consider(tierActive) {
			return best, false
		}
		// 并发窗口：活跃层在级别计算与搜索之间被填满——降到级别 1 继续。
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

	// 每个分层都已满：回退到整体负载最少的槽位，不分分层。一旦负向分层的
	// 容量耗尽，负载最少的槽位很可能是承载流数远少于堆满的健康槽位的 heavy
	// 或 degraded 槽位——堆在那里可以保持负载均衡，而不是把所有流叠到一条
	// 拥挤的健康连接上（这也是压力级别保持真实的原因）。retiring 槽位
	// （degraded+expiring）同样被排除在回退之外，使它们排空到空闲并被退役。
	return p.leastActive(live, recordStats), true
}

// pressureLevel 根据池内负载最少的 active（健康）槽位与池的压力基数推导当前
// 压力级别：
//
//	level 0：minActive < base——活跃层仍有容量，不启用更低的分层；
//	level k (k>=1)：minActive ∈ [2^(k-1)*base, 2^k*base)——每个 active 槽位
//	         都达到或超过 2^(k-1)*base 条流；expiring/heavy/degraded 的
//	         分层容量随 k 缩放（见 tierCap）。
//
// 完全没有健康槽位时（活跃层按定义"已满"），级别退化为池内全局最小值，
// 使更低的分层立即参与，并至少钳制到级别 1。
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

// floorLog2 返回 v > 0 时的 floor(log2(v))。
func floorLog2(v int32) int32 {
	var n int32
	for v > 1 {
		v >>= 1
		n++
	}
	return n
}

// tierCap 返回给定压力级别下某一分层的加权负载容量：该分层的槽位只有在加权
// 负载（active × 负向标记复合权重）低于容量时才接受新流。实际流上限由
// 权重相除得到。
//
//	level 0：只有 active 分层有容量，cap = base；
//	level k>=1：每个负向分层的 cap = 2^(k-1)*base。
//
// 在级别 1，这意味着 heavy 槽位至多容纳 base/4 条流，expiring 槽位 base/8，
// degraded 槽位 base/16——1 条 heavy 流相当于 4 条健康流，1 条 expiring
// 相当于 8，1 条 degraded 相当于 16。每升一级，负向分层的容量翻倍：
// 模型先溢出到负向分层，然后堆回活跃层直到它翻倍，接着负向分层容量翻倍、
// 溢出重新开始——如此循环，直到流结束、负载自然回落。极端级别会超出
// int32 范围；由此产生的负容量被调用方视为"无容量"。
func tierCap(tier slotTier, level, base int32) int32 {
	if level == 0 {
		if tier == tierActive {
			return base
		}
		return 0
	}
	if tier == tierActive {
		// tierActive 在级别 >= 1 时永远不会被主动搜索：按定义每个 active
		// 槽位都已达到或超过当前阈值，因此没有一个能通过容量检查。
		// "堆回活跃层"是 tieredSelect 中的回退路径。
		return 0
	}
	if tier == tierRetiring {
		// tierRetiring 永远不会被搜索：同时 degraded 和 expiring 的槽位
		// 被完全排除在选择之外（见 leastActive）。
		return 0
	}
	return base << (level - 1)
}

// minActiveInTier 返回给定分层各槽位中最小的活跃流数，以及是否存在这样的
// 槽位。只考虑前 `live` 个槽位。
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

// minActiveInRange 返回前 `live` 个槽位中最小的活跃流数；区间内没有槽位时
// 返回 0。
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

// leastActive 返回前 `live` 个槽位中加权流最少的槽位——压力调度器的最终
// 无上限回退；负载相同时负向标记更少的胜出。即将被驱逐的槽位被排除：
// retiring 槽位（degraded 且 expiring）和 draining 槽位（带 expiring 或
// degraded 标记的空闲槽位）绝不能因新流而存活——它们排空到空闲后由健康
// 循环轮换/退役，并通过 grow 由新连接取代。当每个活跃槽位都面临驱逐时，
// 返回其中负载最少的那个，使 pick 永不失败（健康循环会在一两个周期内
// 退役它们，关闭这个窗口）。没有活跃槽位时返回第一个预分配的槽位。
// recordStats 控制 tier_retiring_skipped 计数器的记录
// （grow 路径的饱和检查不得记录调度统计）。
func (p *slotPool) leastActive(live int, recordStats bool) *transportSlot {
	if live == 0 {
		return p.slots[0]
	}
	var best *transportSlot
	var minWeighted int32 = math.MaxInt32
	var minNeg int32 = math.MaxInt32
	var lastResort *transportSlot // 负载最少的 retiring/draining 槽位，绝对的最后手段
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
			// 负载相同的最后手段候选中，忙碌的槽位胜过 draining 槽位：
			// draining 槽位保持空闲，由健康循环驱逐，而不是被重新激活。
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

// grow 再激活一个槽位（存活数至多 maxSlots），优先新连接而不是压榨负向槽位：
// 当流所属池的槽位达到阈值（分层饱和）时，池自我扩容；一旦池达到连接上限，
// 则改扩兄弟池——但只在兄弟池的槽位同样饱和时，这样某个池不会因另一池
// 持续饱和而被逐条流撑大。只有当两个池都到上限时，pick 才回退到分层选择，
// 最后是负载最少的槽位。
//
// grow 报告实际扩容的池及其激活后的存活槽位数；池为 nil 表示没有发生扩容
// （调用方由此知道该请求没有触发扩容）。
//
// 并发：扩容决策与 liveCount 更新发生在同一个临界区内（s.mu 写锁）——
// 无锁快路径只过滤常见的无需扩容情形，任何槽位激活前都会在锁内重新评估
// growTarget。因此并发的扩容者会串行化：第一个激活槽位（使目标池低于
// 饱和），下一个重新检查后退让，并发流永远不会过度扩容池。写锁同时排除
// 并发的 pick（读锁）和 shrink，保持活跃槽位区间一致。首次激活（live == 0）
// 时一次激活两条连接以获得更好的初始吞吐量，因为典型网页浏览会产生超过
// 8 条并发流；maxSlots 为 1 时回退为 1 条。
func (s *slotScheduler) grow(highPriority bool) (*slotPool, int32) {
	pool := s.poolOf(highPriority)
	target, _ := s.growTarget(pool)
	if target == nil {
		return nil, 0
	}

	// 需要新连接——在锁下扩容。
	s.mu.Lock()
	defer s.mu.Unlock()

	// 获取锁后再次检查：等待期间另一个扩容者可能已激活了槽位
	// （或改变了分层）。
	target, live := s.growTarget(pool)
	if target == nil {
		return nil, 0
	}
	// 被重新激活的槽位不得继承前一条连接的轮换状态：shrink/retire 交换删除
	// 槽位时不会清除其标记，因此重新激活的槽位在首次拨号完成前会显示
	// 过期的 expiring/degraded 结论和逾期的截止时间。在槽位变为活跃之前
	// 清零连接作用域的状态；真正的拨号通过 resetConn 重置截止时间。
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

// growTarget 决定是否需要新连接以及它属于哪个池；没有池应扩容时返回 nil。
// 扩容只依据池内部的槽位阈值判断——池只在自己的槽位达到阈值（分层饱和）
// 时扩容，且只要自己的槽位仍有容量，池就绝不会被另一池的流撑大：
//
//   - 流所属池低于上限且分层仍有容量 → 不扩容（pick 正常服务该流）；
//   - 所属池低于上限但分层饱和 → 扩容所属池（新空闲槽位使池回落到饱和
//     之下，因此扩容会自我节流）；
//   - 所属池达到上限且分层饱和 → 扩容兄弟池，但仅在兄弟池同样分层饱和
//     （或尚未激活）时：兄弟池的新槽位随后承载借用的流。兄弟池仍有分层
//     容量时，流会借用它的健康槽位而不是扩容——这限制了跨池扩容，
//     使一个池的持续饱和无法逐条流撑大另一个池；
//   - 所属池达到上限但分层仍有容量 → 不扩容；
//   - 两个池都达到上限 → 不扩容（pick 回退到分层选择，最后是无上限回退）。
func (s *slotScheduler) growTarget(pool *slotPool) (*slotPool, int32) {
	live := pool.liveCount.Load()
	if int(live) < pool.maxSlots {
		if live == 0 || pool.saturatedIn(int(live)) {
			return pool, live
		}
		return nil, 0
	}
	// 所属池已达连接上限：只有当其槽位同样饱和时才需要新连接——否则会在
	// 所属池仍有分层容量时撑大兄弟池。
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

// shrinkIdleLocked 从两个池退役所有空闲槽位（active==0），把每个槽位交换
// 删除到其池的末尾。调用方必须持有 s.mu。
func (s *slotScheduler) shrinkIdleLocked() {
	for _, pool := range []*slotPool{s.priority, s.bulk} {
		for pool.removeIdleLocked() {
		}
	}
}

// removeIdleLocked 从池的活跃计数中交换删除第一个空闲槽位。没有空闲槽位
// 时返回 false。调用方必须持有 s.mu。
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

// removeAtLocked 把位置 i 的槽位从池的存活集合中交换删除（swap-remove）。
// 调用方必须持有 s.mu。
func (p *slotPool) removeAtLocked(i, live int) {
	last := live - 1
	if i != last {
		p.slots[i], p.slots[last] = p.slots[last], p.slots[i]
	}
	p.liveCount.Add(-1)
}

// remove 在槽位仍处于活跃状态且不承载流时，把它从所属池的存活集合中
// 交换删除（swap-remove），并报告删除是否发生。流数会在锁内重新检查，
// 避免并发的 Open 把新流放到正在被移除的槽位上。槽位所属的池通过扫描
// 两个池的指针找到：每个池独立地从 0 编号自己的槽位，仅凭稳定 idx 无法
// 定位池。该函数很少被调用（退役空闲的降级槽位时），因此对预分配数组做
// 线性扫描没有问题。
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
