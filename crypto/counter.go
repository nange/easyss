package crypto

import (
	"encoding/binary"
	"sync/atomic"
)

type CounterNonce struct {
	ctr    atomic.Uint64
	prefix [4]byte
}

func NewCounterNonce(prefix [4]byte) *CounterNonce {
	return &CounterNonce{prefix: prefix}
}

func (cn *CounterNonce) Next() [12]byte {
	var nonce [12]byte
	copy(nonce[:4], cn.prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], cn.ctr.Add(1)-1)
	return nonce
}
