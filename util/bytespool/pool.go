// Package bytespool provides a pool of []byte.
package bytespool

// Ref: github.com/Dreamacro/clash/common/pool

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
