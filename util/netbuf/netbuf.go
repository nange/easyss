// Package netbuf 提供从 bytespool 借出、按需增长的读缓冲，避免读缓冲随并发流峰值线性占用内存。
// 只适用于 TCP 这类缓冲短了只会多读几次的流：UDP 绝不能用，超长数据报会被静默截断。
package netbuf

import (
	"github.com/nange/easyss/v3/util/bytespool"
)

const Hint = 4 * 1024

// Reader 是一个按需增长的池化读缓冲，不实现 io.Reader，生命周期由调用方掌控。
// 不是并发安全的：一个 Reader 属于一条流的一个读取方向。
type Reader struct {
	buf []byte
	// max 是缓冲的容量上限，且已归一到池内合法档位；达到它之后 Grow 不再动作。
	max int
}

// NewReader 返回初始档位为 hint 的读缓冲，hint 与 max 都归一到 bytespool 的 2 的幂档位；
// max 另被钳到 bytespool.MaxSize，池对更大请求返回 nil 会让 Buf() 变 nil、Read 空转。
func NewReader(hint, max int) *Reader {
	max = min(normalized(max, Hint), bytespool.MaxSize)
	hint = min(normalized(hint, Hint), max)
	return &Reader{buf: bytespool.Get(hint), max: max}
}

// Buf 返回当前缓冲，len 与 cap 相等，调用方用 len(buf) 判断这次是否读满。
func (r *Reader) Buf() []byte {
	return r.buf
}

func (r *Reader) Cap() int {
	return cap(r.buf)
}

// Grow 把缓冲升一档（最多到构造时的 max），达到上限后是 no-op。只能在上一次读取读满
// 当前缓冲时调用：Reader 不持有读取结果，`n == len(buf)` 这个前提只能由调用方保证。
func (r *Reader) Grow() {
	cur := cap(r.buf)
	next := r.max
	if double := cur * 2; double < next {
		next = double
	}
	if next <= cur {
		return
	}
	// 先取新缓冲、再归还旧的、最后换字段——三步都在 SwapIn 内完成，因此不存在
	// "取到新缓冲却忘了赋值"的窗口（那会让 r.buf 指向一块已入池的缓冲）。
	bytespool.SwapIn(&r.buf, bytespool.Get(next))
}

// Release 把当前缓冲归还池；调用方必须保证此后不再使用 Buf 的结果，且不得重复调用。
func (r *Reader) Release() {
	if cap(r.buf) > 0 {
		bytespool.MustPut(r.buf[:cap(r.buf)])
	}
	r.buf = nil
}

// normalized 把 size 归一到 bytespool 的合法档位：非正值退化为 fallback，否则向上取到 2 的幂。
func normalized(size, fallback int) int {
	if size <= 0 {
		size = fallback
	}
	class := 1
	for class < size {
		class <<= 1
	}
	return class
}
