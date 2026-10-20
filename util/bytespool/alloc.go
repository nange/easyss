package bytespool

import (
	"errors"
	"math/bits"
	"sync"
	"sync/atomic"
)

var defaultAllocator = NewAllocator()

// MaxSize 是缓冲池能提供的最大缓冲区大小；更大的请求 Get 返回 nil，Put 会拒绝。
const MaxSize = 131072

// 每个档位最多保留的块数：sync.Pool 本身不设上限，服务端的 64KB 缓冲区在数千并发流下
// 一次峰值就会常驻数百 MB 且不还给操作系统。
const defaultMaxRetainedPerClass = 64

type Allocator struct {
	buffers []sync.Pool
	// 与 sync.Pool 的实际内容只可能偏大（GC 清池不通知），偏差只让 Put 更早停止保留，属安全侧。
	retained []atomic.Int64
	// 每个档位的保留上限，<=0 表示不限制。
	maxRetained int64
}

// NewAllocator 返回默认上限的分配器；请求不超过 MaxSize 时空间浪费不超过 50%。
func NewAllocator() *Allocator {
	return NewAllocatorWithLimit(defaultMaxRetainedPerClass)
}

// maxRetained <= 0 表示不限制每个档位的保留量。
func NewAllocatorWithLimit(maxRetained int) *Allocator {
	alloc := new(Allocator)
	alloc.maxRetained = int64(maxRetained)
	alloc.buffers = make([]sync.Pool, 18) // 1B -> 128K
	alloc.retained = make([]atomic.Int64, 18)
	for k := range alloc.buffers {
		i := k
		alloc.buffers[k].New = func() any {
			return make([]byte, 1<<uint32(i))
		}
	}
	return alloc
}

func (alloc *Allocator) Get(size int) []byte {
	if size <= 0 || size > MaxSize {
		return nil
	}

	bits := msb(size)
	if size == 1<<bits {
		return alloc.get(bits)[:size]
	}

	return alloc.get(bits + 1)[:size]
}

// 命中 New 时也递减计数：计数只在 Put 时递增而 GC 清池不通知，那正是排掉"幻影"的唯一时机；
// 若只在命中池时递减，档位会在第一次 GC 清池后永久停止保留。
func (alloc *Allocator) get(bits uint16) []byte {
	decRetained(&alloc.retained[bits])
	return alloc.buffers[bits].Get().([]byte)
}

// 负值用 CAS 修正回 0 而不是 Store：并发的另一个 Get 刚加上的额度不能被一并抹掉。
func decRetained(c *atomic.Int64) {
	for {
		cur := c.Load()
		if cur <= 0 {
			if c.CompareAndSwap(cur, 0) {
				return
			}
			continue
		}
		if c.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}

// Put 要求 cap 恰好是 2 的 n 次幂。返回非 nil 只表示缓冲区不合约定；达到保留上限时同样返回
// nil 但不再保留该缓冲区，调用方（多为 MustPut）无需区分两者。
func (alloc *Allocator) Put(buf []byte) error {
	bits := msb(cap(buf))
	if cap(buf) == 0 || cap(buf) > MaxSize || cap(buf) != 1<<bits {
		return errors.New("allocator Put() incorrect buffer size")
	}

	if alloc.maxRetained > 0 && alloc.retained[bits].Add(1) > alloc.maxRetained {
		alloc.retained[bits].Add(-1)
		return nil
	}

	//nolint
	//lint:ignore SA6002 ignore temporarily
	alloc.buffers[bits].Put(buf)
	return nil
}

func msb(size int) uint16 {
	return uint16(bits.Len32(uint32(size)) - 1)
}
