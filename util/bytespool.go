package util

import (
	"sync"
)

// Bytes is a pool of byte slices that can be re-used.
type Bytes struct {
	pool *sync.Pool
}

// NewBytes returns a Bytes pool
func NewBytes(capSize int) *Bytes {
	return &Bytes{
		pool: &sync.Pool{New: func() interface{} {
			return make([]byte, 0, capSize)
		}},
	}
}

// Get returns a byte slice size with at least sz capacity
func (p *Bytes) Get(sz int) []byte {
	c := p.pool.Get().([]byte)
	if cap(c) < sz {
		return make([]byte, sz)
	}

	return c[:sz]
}

// Put returns a slice back to the pool
func (p *Bytes) Put(c []byte) {
	p.pool.Put(c)
}
