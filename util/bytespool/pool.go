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
