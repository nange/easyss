package util

import (
	"encoding/binary"
	"math/rand"
	"sync"
)

var lenPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 4)
		return buf
	},
}

func EncodeHTTP2DataFrameHeader(datalen int, dst []byte) (header []byte) {
	if len(dst) < 9 {
		dst = make([]byte, 9)
	} else if len(dst) > 9 {
		dst = dst[:9]
	}

	length := lenPool.Get().([]byte)
	defer lenPool.Put(length)

	binary.BigEndian.PutUint32(length, uint32(datalen))
	// set length field
	copy(dst[:3], length[1:])
	// set frame type to data
	dst[3] = 0x0
	// set default flag
	dst[4] = 0x0

	// set stream identifier. note: this is temporary, will update in future
	binary.BigEndian.PutUint32(dst[5:9], uint32(rand.Int31()))

	return dst
}

func EncodeFINRstStreamHeader(dst []byte) (header []byte) {
	if len(dst) < 9 {
		dst = make([]byte, 9)
	} else if len(dst) > 9 {
		dst = dst[:9]
	}
	binary.BigEndian.PutUint16(dst[1:3], uint16(4))
	// set frame type to RST_STREAM
	dst[3] = 0x7
	// set default flag
	dst[4] = 0x0

	// set stream identifier. note: this is temporary, will update in future
	binary.BigEndian.PutUint32(dst[5:9], uint32(rand.Int31()))

	return dst
}

func EncodeACKRstStreamHeader(dst []byte) (header []byte) {
	if len(dst) < 9 {
		dst = make([]byte, 9)
	} else if len(dst) > 9 {
		dst = dst[:9]
	}
	binary.BigEndian.PutUint16(dst[1:3], uint16(4))
	// set frame type to RST_STREAM
	dst[3] = 0x7
	// set default flag
	dst[4] = 0x1

	// set stream identifier. note: this is temporary, will update in future
	binary.BigEndian.PutUint32(dst[5:9], uint32(rand.Int31()))

	return dst
}
