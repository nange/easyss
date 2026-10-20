// Package bytespool 提供 []byte 缓冲池，参考 github.com/Dreamacro/clash/common/pool。
package bytespool

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

// SwapIn 用 buf 顶替 *dst：先归还 *dst 的旧缓冲，再装 buf。buf == nil（池里没有更大的
// 档位）时 *dst 原样保留且不归还，否则后续写入会落进已入池的缓冲。swap 必须在函数内完成，
// 把赋值留给调用方等于让 *dst 指向一块随时可能被别人取走的缓冲；本函数不做别名检测。
func SwapIn(dst *[]byte, buf []byte) {
	if buf == nil {
		return
	}
	if old := *dst; cap(old) > 0 {
		MustPut(old[:cap(old)])
	}
	*dst = buf
}
