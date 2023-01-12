package util

import (
	"encoding/binary"
	"math/rand"

	"github.com/nange/easyss/util/bytespool"
)

const Http2HeaderLen = 9

type ProtoType uint8

const (
	ProtoTypeTCP ProtoType = iota
	ProtoTypeUDP
	ProtoTypePing
	ProtoTypeUnknown
)

func ParseProtoTypeFrom(i uint8) ProtoType {
	switch ProtoType(i) {
	case ProtoTypeTCP:
		return ProtoTypeTCP
	case ProtoTypeUDP:
		return ProtoTypeUDP
	case ProtoTypePing:
		return ProtoTypePing
	default:
		return ProtoTypeUnknown
	}
}

func (pt ProtoType) ToUint8() uint8 {
	return uint8(pt)
}

func EncodeHTTP2Header(protoType ProtoType, datalen int, dst []byte) (header []byte) {
	if cap(dst) < Http2HeaderLen {
		dst = make([]byte, Http2HeaderLen)
	} else {
		dst = dst[:Http2HeaderLen]
	}

	length := bytespool.Get(4)
	defer bytespool.MustPut(length)

	binary.BigEndian.PutUint32(length, uint32(datalen))
	// set length field
	copy(dst[:3], length[1:])
	// set frame type
	dst[3] = protoType.ToUint8()
	// set default flag
	dst[4] = 0x0
	if datalen < 256 { // data has padding field
		// data payload size less than 512 bytes, we add padding field
		dst[4] = 0x8
	}

	// set stream identifier. note: this is temporary, will update in future
	binary.BigEndian.PutUint32(dst[5:Http2HeaderLen], uint32(rand.Int31()))

	return dst
}

func EncodeFINRstStream(dst []byte) (header []byte) {
	if cap(dst) < Http2HeaderLen {
		dst = make([]byte, Http2HeaderLen)
	} else {
		dst = dst[:Http2HeaderLen]
	}
	binary.BigEndian.PutUint16(dst[1:3], uint16(4))
	// set frame type to RST_STREAM
	dst[3] = 0x7
	// set default flag
	dst[4] = 0x0

	// set stream identifier. note: this is temporary, will update in future
	binary.BigEndian.PutUint32(dst[5:Http2HeaderLen], uint32(rand.Int31()))

	return dst
}

func EncodeACKRstStream(dst []byte) (header []byte) {
	if cap(dst) < Http2HeaderLen {
		dst = make([]byte, Http2HeaderLen)
	} else {
		dst = dst[:Http2HeaderLen]
	}
	binary.BigEndian.PutUint16(dst[1:3], uint16(4))
	// set frame type to RST_STREAM
	dst[3] = 0x7
	// set default flag
	dst[4] = 0x1

	// set stream identifier. note: this is temporary, will update in future
	binary.BigEndian.PutUint32(dst[5:Http2HeaderLen], uint32(rand.Int31()))

	return dst
}
