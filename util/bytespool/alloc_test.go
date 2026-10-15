package bytespool

import (
	"math/rand/v2"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllocGet(t *testing.T) {
	alloc := NewAllocator()
	assert.Nil(t, alloc.Get(0))
	assert.Equal(t, 1, len(alloc.Get(1)))
	assert.Equal(t, 2, len(alloc.Get(2)))
	assert.Equal(t, 3, len(alloc.Get(3)))
	assert.Equal(t, 4, cap(alloc.Get(3)))
	assert.Equal(t, 4, cap(alloc.Get(4)))
	assert.Equal(t, 1023, len(alloc.Get(1023)))
	assert.Equal(t, 1024, cap(alloc.Get(1023)))
	assert.Equal(t, 1024, len(alloc.Get(1024)))
	assert.Equal(t, 65536, len(alloc.Get(65536)))
	assert.Equal(t, 131072, cap(alloc.Get(65537)))
	assert.Equal(t, 131072, len(alloc.Get(131072)))
	assert.Nil(t, alloc.Get(131073))
}

func TestAllocPut(t *testing.T) {
	alloc := NewAllocator()
	assert.NotNil(t, alloc.Put(nil), "put nil misbehavior")
	assert.NotNil(t, alloc.Put(make([]byte, 3)), "put elem:3 []bytes misbehavior")
	assert.Nil(t, alloc.Put(make([]byte, 4)), "put elem:4 []bytes misbehavior")
	assert.Nil(t, alloc.Put(make([]byte, 1023, 1024)), "put elem:1024 []bytes misbehavior")
	assert.Nil(t, alloc.Put(make([]byte, 65536)), "put elem:65536 []bytes misbehavior")
	assert.NotNil(t, alloc.Put(make([]byte, 65537)), "put elem:65537 []bytes misbehavior")
	assert.Nil(t, alloc.Put(make([]byte, 131072)), "put elem:131072 []bytes misbehavior")
	assert.NotNil(t, alloc.Put(make([]byte, 131073)), "put elem:131073 []bytes misbehavior")
}

func TestAllocPutThenGet(t *testing.T) {
	alloc := NewAllocator()
	data := alloc.Get(4)
	assert.Nil(t, alloc.Put(data))
	newData := alloc.Get(4)

	assert.Equal(t, cap(data), cap(newData), "different cap while alloc.Get()")
}

// TestAllocRetentionLimitDoesNotBreakCallers 固定"达到保留上限只是丢弃，
// 不是错误"这一契约：调用方（多为 MustPut）无需区分"池满"与"成功"，
// 池满时缓冲区交给 GC，Get 始终可用。
//
// 这里不断言计数器的具体数值：GC 会静默清空 sync.Pool，使计数器相对池的
// 真实内容偏大（偏大只会让 Put 更早停止保留，属安全侧），因此计数器是
// 近似量，不是可断言的精确量。
func TestAllocRetentionLimitDoesNotBreakCallers(t *testing.T) {
	const limit = 4
	alloc := NewAllocatorWithLimit(limit)

	for range limit * 8 {
		assert.Nil(t, alloc.Put(make([]byte, 1024)), "Put 在达到保留上限时不应报错")
	}
	for range limit * 4 {
		assert.Equal(t, 1024, cap(alloc.Get(1024)), "Get 必须始终返回可用缓冲区")
	}
}

// TestAllocRetentionLimitDropsInsteadOfAllocating 验证"超过上限的缓冲区被丢弃，
// 且丢弃动作本身不做任何分配"——它只是把缓冲区交给 GC，既不阻塞也不额外分配。
//
// 缓冲区在测量窗口之外预先建好：make([]byte, ...) 自身就是一次分配，
// 把它算进来这条断言就失去意义了。
func TestAllocRetentionLimitDropsInsteadOfAllocating(t *testing.T) {
	const limit = 4
	alloc := NewAllocatorWithLimit(limit)

	// 先填满额度，让后续的 Put 全部走"丢弃"分支。
	for range limit {
		assert.Nil(t, alloc.Put(make([]byte, 1024)))
	}

	const dropped = 1000
	bufs := make([][]byte, dropped)
	for i := range bufs {
		bufs[i] = make([]byte, 1024)
	}

	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, b := range bufs {
		assert.Nil(t, alloc.Put(b), "超额 Put 不应报错")
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if grown := after.Mallocs - before.Mallocs; grown > 0 {
		t.Fatalf("丢弃 %d 个超额缓冲区时发生了 %d 次分配，期望 0 次", dropped, grown)
	}
}

// TestAllocRetentionLimitUnlimited 验证 maxRetained <= 0 表示不限制保留。
//
// 这种模式下计数器刻意不递增（没有上限就无需跟踪），因此不断言计数器，
// 只固定它对调用方可见的行为：Put/Get 照常工作。
func TestAllocRetentionLimitUnlimited(t *testing.T) {
	alloc := NewAllocatorWithLimit(0)
	for range 200 {
		assert.Nil(t, alloc.Put(make([]byte, 256)), "无上限模式下 Put 不应报错")
	}
	for range 100 {
		assert.Equal(t, 256, cap(alloc.Get(256)), "无上限模式下 Get 必须可用")
	}
}

// TestAllocRetainedCounterDoesNotBlockReuse 验证计数器偏高（GC 清空池时会
// 出现）不会让 Get 失败：Get 始终返回可用缓冲区，必要时新分配。
func TestAllocRetainedCounterDoesNotBlockReuse(t *testing.T) {
	alloc := NewAllocatorWithLimit(8)
	// 人为把计数器抬高到超过实际内容，模拟 GC 已经清空池的情况。
	alloc.retained[msb(512)].Store(1 << 20)

	buf := alloc.Get(512)
	assert.Equal(t, 512, len(buf))
	assert.Equal(t, 512, cap(buf))
}

// TestAllocGetClearsPhantomRetainedCount 固定一条 load-bearing 的行为：
// Get 必须递减保留计数，**包括池为空、由 New 现场分配的那一次**。
//
// 计数只在 Put 时递增，而 GC 清空 sync.Pool 不会通知我们，于是计数会留下
// "幻影"（偏大而池实际为空）。命中 New 说明池里确实没有这一块，此时递减
// 正是排掉幻影的唯一时机；若改成"仅命中池时才递减"，档位会在第一次 GC 清池
// 后永久停止保留——计数再也降不下来，Put 会一直被判定为超额。
func TestAllocGetClearsPhantomRetainedCount(t *testing.T) {
	const limit = 8
	alloc := NewAllocatorWithLimit(limit)
	idx := msb(512)

	// 池是空的，计数器却很大：这就是 GC 清池之后的形态。
	alloc.retained[idx].Store(1000)

	// pool-hit 与 New-hit 在返回值上无法区分（每个档位的 New 恒定设置），
	// 但两者都必须递减计数。
	_ = alloc.Get(512)
	assert.Less(t, alloc.retained[idx].Load(), int64(1000), "Get 应递减保留计数")

	// 幻影未排空期间，Put 一律被判定为超额而丢弃。
	assert.Nil(t, alloc.Put(make([]byte, 512)))
	assert.LessOrEqual(t, alloc.retained[idx].Load(), int64(1000)-1,
		"幻影未排空时 Put 不应递增计数")

	// 持续 Get 会把幻影彻底排空——这正是"仅 pool-hit 才递减"做不到的事。
	for alloc.retained[idx].Load() > 0 {
		_ = alloc.Get(512)
	}
	assert.Zero(t, alloc.retained[idx].Load(), "幻影计数应被排空")

	// 排空之后 Put 必须重新开始保留：借"计数器被占用"这一可观测状态断言。
	assert.Nil(t, alloc.Put(make([]byte, 512)))
	assert.Equal(t, int64(1), alloc.retained[idx].Load(), "幻影排空后 Put 应重新开始保留")
}

// TestSwapIn 固定"换一块更大的缓冲"这条公共路径的三种语义。它存在的意义是
// 把归还顺序收敛到一处：调用方各自写一遍时最容易漏掉的是"池取不到更大缓冲时
// 不得归还旧缓冲"——那会让后续写入落进已经入池的缓冲，造成跨流数据污染。
func TestSwapIn(t *testing.T) {
	t.Run("nil 新缓冲保留旧缓冲", func(t *testing.T) {
		old := Get(1024)
		old[0] = 0xAB
		SwapIn(nil, old[:0])
		// 旧缓冲没有被归还：cap 不变、内容仍然可读。
		assert.Equal(t, 1024, cap(old))
		assert.Equal(t, byte(0xAB), old[0], "池取不到新缓冲时旧缓冲不得被归还")
		MustPut(old)
	})

	t.Run("nil 旧缓冲不 panic", func(t *testing.T) {
		SwapIn(Get(1024), nil)
	})

	t.Run("空 cap 旧缓冲不 panic", func(t *testing.T) {
		SwapIn(Get(1024), []byte{})
	})

	t.Run("正常路径归还旧缓冲", func(t *testing.T) {
		old := Get(1024)
		buf := Get(2048)
		SwapIn(buf, old[:0])
		assert.Equal(t, 2048, cap(buf))
		// 旧缓冲已归还：它仍是合法档位，因此再 Put 一次不会报错
		//（Put 只做档位校验；这条断言固定"归还走的是正常路径"）。
		assert.NoError(t, Put(old))
		MustPut(buf)
	})
}

func BenchmarkMSB(b *testing.B) {
	for b.Loop() {
		msb(rand.Int())
	}
}
