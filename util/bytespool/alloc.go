package bytespool

// 灵感来源于 https://github.com/xtaci/smux/blob/master/alloc.go

import (
	"errors"
	"math/bits"
	"sync"
	"sync/atomic"
)

var defaultAllocator = NewAllocator()

// MaxSize 是缓冲池能够提供的最大缓冲区大小：对于更大的请求 Get 返回 nil，
// Put 会拒绝 cap 更大的缓冲区。
const MaxSize = 131072

// defaultMaxRetainedPerClass 是每个大小档位最多保留的缓冲区数量（默认 64 块）。
//
// sync.Pool 本身对保留量没有任何上限：unbounded 的 Put 会把历史峰值全部钉在
// 进程里，而"峰值"恰恰是最不该常驻的量。服务端的明文缓冲区是 64KB 级别的，
// 数千并发流一次峰值就能留下数百 MB；不设上限的话，即使流量早已回落，
// 这部份内存也不会归还给操作系统（实测：600 条流关闭 30s 后 RSS 仍停在峰值）。
//
// 64 块 × 最大档位 128KB = 单档位最多 8MB，而大档位在实际负载里几乎不出现，
// 因此总量与"峰值并发"解耦。超出上限的缓冲区直接交给 GC（Put 不报错，
// 调用方无需区分"池满"与"成功"）。
const defaultMaxRetainedPerClass = 64

// Allocator 用于管理入站帧的缓冲区，经过优化以避免清零后被覆盖
type Allocator struct {
	buffers []sync.Pool
	// retained 记录每个档位"当前保留在池里"的块数。它与 sync.Pool 的实际内容
	// 只可能偏大（GC 清空池时不会通知我们），而这个方向的偏差只会让 Put 更早
	// 地停止保留，属安全侧。
	retained []atomic.Int64
	// maxRetained 是每个档位的保留上限，<=0 表示不限制。
	maxRetained int64
}

// NewAllocator 初始化一个 []byte 分配器，用于不超过 131072 字节的帧，
// 空间分配的浪费（内存碎片）保证不超过 50%，且每个大小档位的常驻缓冲区
// 数量有上限（见 defaultMaxRetainedPerClass）。
func NewAllocator() *Allocator {
	return NewAllocatorWithLimit(defaultMaxRetainedPerClass)
}

// NewAllocatorWithLimit 与 NewAllocator 相同，但可指定每个档位的保留上限，
// 便于测试与需要精确控制常驻量的场景；maxRetained <= 0 表示不限制。
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

// Get 从池中获取一个 cap 最合适的 []byte
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

// get 从指定档位取出一块缓冲区：优先复用池中的，池为空时按 New 新分配。
func (alloc *Allocator) get(bits uint16) []byte {
	if buf, ok := alloc.buffers[bits].Get().([]byte); ok {
		// 从池中取出才递减：命中 New 时池里本来就没有这一块。
		decRetained(&alloc.retained[bits])
		return buf
	}
	return make([]byte, 1<<uint32(bits))
}

// decRetained 递减保留计数，并把可能的负值 CAS 修正回 0。
//
// 计数只可能偏大（GC 清空池时不通知我们），此时 Get 找不到块、不会走到这里；
// 并发 Get 与 GC 清池交错时可能出现短暂的负值，用 CAS 修正而非直接 Store，
// 以免并发的另一个 Get 刚加上的额度被一并抹掉。
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

// Put 将 []byte 归还到池中以备将来使用，其 cap 必须恰好是 2 的 n 次幂。
//
// 返回非 nil 只表示"这个缓冲区不符合池的约定"（cap 不是 2 的幂、超过
// MaxSize、或为空）。达到保留上限时 Put 返回 nil 但不再保留该缓冲区，
// 它会被 GC 回收——调用方（多为 MustPut）无需区分这两种情况。
func (alloc *Allocator) Put(buf []byte) error {
	bits := msb(cap(buf))
	if cap(buf) == 0 || cap(buf) > MaxSize || cap(buf) != 1<<bits {
		return errors.New("allocator Put() incorrect buffer size")
	}

	// 先占额度再入池：超额时直接丢弃，避免池无上限增长。
	if alloc.maxRetained > 0 && alloc.retained[bits].Add(1) > alloc.maxRetained {
		alloc.retained[bits].Add(-1)
		return nil
	}

	//nolint
	//lint:ignore SA6002 ignore temporarily
	alloc.buffers[bits].Put(buf)
	return nil
}

// msb 返回最高有效位的位置
func msb(size int) uint16 {
	return uint16(bits.Len32(uint32(size)) - 1)
}
