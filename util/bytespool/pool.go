// Package bytespool 提供 []byte 缓冲池。
package bytespool

// 参考：github.com/Dreamacro/clash/common/pool

func Get(size int) []byte {
	return defaultAllocator.Get(size)
}

func Put(buf []byte) error {
	return defaultAllocator.Put(buf)
}

func MustPut(buf []byte) {
	if err := Put(buf); err != nil {
		panic(err)
	}
}

// SwapIn 用 buf 顶替 *dst：先把 *dst 指向的旧缓冲归还池，再把 buf 装进 *dst。
// 它是一条"换一块更大的缓冲"的公共路径：全仓有多处"读满就换块更大的"逻辑，
// 各自写一遍极易漏掉归还顺序，或漏掉池取不到缓冲时的判断。
//
// 它取指针而不是"归还旧的、把赋值留给调用方"，是因为 swap 必须由这里完成：
// 调用方一旦在调用之后忘了赋值，*dst 就会指向一块已经入池、随时可能被别的流
// 取走的缓冲——那正是本函数要防的跨流数据污染。
//
// 语义：
//   - buf == nil：池拿不到更大的缓冲（请求超过 MaxSize）。*dst 原样保留、
//     旧缓冲不归还（否则后续写入会落进已入池的缓冲）。
//   - cap(*dst) == 0：没有东西可归还，不做任何校验。
//   - 前提：buf 必须与 *dst 指向的缓冲不同。本函数不做别名检测（len(*dst) == 0
//     时也无从检测），SwapIn(&x, x[:0]) 会把 x 归还之后又装回 x，调用方此后就在
//     使用一块已经入池的缓冲。
//   - 其余情况要求 cap(*dst) 是池内合法档位（2 的幂且 <= MaxSize），否则 panic：
//     调用方持有的一定是 Get 出来的缓冲，违反该前提即编程错误。
func SwapIn(dst *[]byte, buf []byte) {
	if buf == nil {
		return
	}
	if old := *dst; cap(old) > 0 {
		MustPut(old[:cap(old)])
	}
	*dst = buf
}
