package bytespool

// 灵感来源于 https://github.com/xtaci/smux/blob/master/alloc.go

import (
	"errors"
	"math/bits"
	"sync"
)

var defaultAllocator = NewAllocator()

// MaxSize 是缓冲池能够提供的最大缓冲区大小：对于更大的请求 Get 返回 nil，
// Put 会拒绝 cap 更大的缓冲区。
const MaxSize = 131072

// Allocator 用于管理入站帧的缓冲区，经过优化以避免清零后被覆盖
type Allocator struct {
	buffers []sync.Pool
}

// NewAllocator 初始化一个 []byte 分配器，用于不超过 131072 字节的帧，
// 空间分配的浪费（内存碎片）保证不超过 50%。
func NewAllocator() *Allocator {
	alloc := new(Allocator)
	alloc.buffers = make([]sync.Pool, 18) // 1B -> 128K
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
		return alloc.buffers[bits].Get().([]byte)[:size]
	}

	return alloc.buffers[bits+1].Get().([]byte)[:size]
}

// Put 将 []byte 归还到池中以备将来使用，
// 其 cap 必须恰好是 2 的 n 次幂
func (alloc *Allocator) Put(buf []byte) error {
	bits := msb(cap(buf))
	if cap(buf) == 0 || cap(buf) > MaxSize || cap(buf) != 1<<bits {
		return errors.New("allocator Put() incorrect buffer size")
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
