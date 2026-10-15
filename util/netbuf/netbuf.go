// Package netbuf 提供从 bytespool 借出、按需增长的读缓冲。
//
// 它解决的是"每流急切预留一大块读缓冲"这一类内存形态：一条流的读缓冲常常
// 在流的整个生命周期内被钉住（goroutine 阻塞在 Read 上时正持着它），而实际
// 读到的数据远小于预留量。空闲流、心跳流与只传少量数据的流因此各占一整块，
// 服务端内存随峰值并发流数线性增长，且峰值过后不回落。
//
// 增长是**按需**的：唯一触发条件是"读满了当前缓冲"（n == len(buf)）。读满
// 说明对端可能还有更多数据，值得升一档；读不满说明当前档位已经够用，此时
// 增长只会白白抬高常驻内存。
//
// 它只适用于 TCP 这类"缓冲短了只会多几次 Read、数据不会丢"的流式读取。
// **UDP 绝不能用它**：超长数据报会被静默截断（Go 的 UDP Read 丢弃
// recvfrom 的 MSG_TRUNC 标志且不上报），截断后没有重读机会。
package netbuf

import (
	"github.com/nange/easyss/v3/util/bytespool"
)

// Hint 是读缓冲的默认初始档位。它是"流"这个维度的常驻内存下限：绝大多数
// 流只在小数据量上活动，把它们从一整块读缓冲降到这么小是收益最大的一项。
const Hint = 4 * 1024

// Reader 是一个按需增长的池化读缓冲。它不实现 io.Reader，只提供"拿缓冲给
// conn.Read / 读满后请增长"这两个动作，使调用方自己掌控生命周期（谁读、
// 何时归还都在调用方作用域内可见）。
//
// 不是并发安全的：一个 Reader 属于一条流的一个读取方向。
type Reader struct {
	buf []byte
	// max 是缓冲的容量上限，且已归一到池内合法档位。达到它之后 Grow 不再动作。
	max int
}

// NewReader 返回一个初始档位为 hint 的读缓冲。hint <= 0 时取 Hint；hint
// 超过 max 时取 max。两个值都会被归一到 bytespool 的合法档位（2 的幂：
// 池的 Get 按档位返回，Put 也要求 cap 恰好是 2 的幂）。
func NewReader(hint, max int) *Reader {
	max = normalized(max, Hint)
	hint = min(normalized(hint, Hint), max)
	return &Reader{buf: bytespool.Get(hint), max: max}
}

// Buf 返回当前缓冲。它的 len 与 cap 相等（都是当前档位），因此调用方可以
// 直接用 len(buf) 判断"这次是否读满"，进而决定要不要 Grow。
func (r *Reader) Buf() []byte {
	return r.buf
}

// Cap 返回当前档位，供测试与日志观察增长行为。
func (r *Reader) Cap() int {
	return cap(r.buf)
}

// Grow 把缓冲升一档（2 倍摊销），上限是构造时的 max。调用方必须在"上一次
// 读取读满了当前缓冲"时才调用它：Reader 不持有读取结果，因此无法替调用方
// 判断"是否读满"，这个前提只能由调用方用 `n == len(buf)` 保证。
//
// 达到上限后它是 no-op：继续增长既没有收益，也超出调用方声明的预算。
// 换下来的旧缓冲通过 bytespool.SwapIn 归还；如果池取不到新缓冲（档位超过
// MaxSize），SwapIn 保留旧缓冲，本方法也不会让 r.buf 变成 nil。
func (r *Reader) Grow() {
	cur := cap(r.buf)
	next := r.max
	if double := cur * 2; double < next {
		next = double
	}
	if next <= cur {
		return
	}
	// 先取新缓冲、再归还旧的、最后才换字段：SwapIn 之后旧缓冲已入池，
	// 而字段仍指向它，因此赋值必须紧跟在 SwapIn 之后（中间不能有任何可能
	// 提前返回或读取 r.buf 的语句）。
	buf := bytespool.Get(next)
	bytespool.SwapIn(buf, r.buf[:0])
	r.buf = buf
}

// Release 把当前缓冲归还池。调用方必须保证此后不再使用 Buf 的结果（通常
// 写成 defer r.Release()）。不得重复调用。
func (r *Reader) Release() {
	if cap(r.buf) > 0 {
		bytespool.MustPut(r.buf[:cap(r.buf)])
	}
	r.buf = nil
}

// normalized 把 size 归一到 bytespool 的合法档位：非正值退化为 fallback，
// 否则向上取到 2 的幂（Get 按档位返回，Put 的 2 的幂不变式也要求它是档位）。
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
