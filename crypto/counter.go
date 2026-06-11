package crypto

import (
	"encoding/binary"
)

type CounterNonce struct {
	ctr    uint64
	prefix [4]byte
}

func NewCounterNonce(prefix [4]byte) *CounterNonce {
	return &CounterNonce{prefix: prefix}
}

func (cn *CounterNonce) Next() [12]byte {
	var nonce [12]byte
	copy(nonce[:4], cn.prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], cn.ctr)
	cn.ctr++
	return nonce
}
