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

// SwapIn 用 buf 顶替 old，并把 old 归还池。它是一条"换一块更大的缓冲"的
// 公共路径：全仓有多处"读满就换块更大的"逻辑，各自写一遍归还顺序极易漏掉
// old 的归还或漏掉池取不到缓冲时的判断，而漏掉归还就是把缓冲泄漏给 GC——
// 正是这次内存收敛要杜绝的形态。
//
// 语义：
//   - buf == nil：池拿不到更大的缓冲（请求超过 MaxSize）。调用方选择维持
//     原状，因此 old 原样保留、不归还（否则后续写入会落进已入池的缓冲）。
//   - old == nil 或 cap(old) == 0：没有东西可归还，不做任何校验。
//   - 其余情况要求 cap(old) 是池内合法档位（2 的幂且 <= MaxSize），否则 panic：
//     调用方持有的一定是 Get 出来的缓冲，违反该前提即编程错误。
func SwapIn(buf, old []byte) {
	if buf == nil {
		return
	}
	if cap(old) > 0 {
		MustPut(old[:cap(old)])
	}
}
