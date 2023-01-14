package util

import (
	"encoding/binary"
	"math/rand"

	"github.com/nange/easyss/util/bytespool"
)

const (
	Http2HeaderLen = 9
	PaddingSize    = 64
	MaxPaddingSize = 255
	MinPaddingSize = 64
)

type ProtoType uint8

const (
	ProtoTypeTCP ProtoType = iota
	ProtoTypeUDP
	ProtoTypeUnknown
)

func ParseProtoTypeFrom(i uint8) ProtoType {
	switch ProtoType(i) {
	case ProtoTypeTCP:
		return ProtoTypeTCP
	case ProtoTypeUDP:
		return ProtoTypeUDP
	default:
		return ProtoTypeUnknown
	}
}

func (pt ProtoType) ToUint8() uint8 {
	return uint8(pt)
}

func (pt ProtoType) String() string {
	switch pt {
	case ProtoTypeTCP:
		return "tcp"
	case ProtoTypeUDP:
		return "udp"
	default:
		return "unknown"
	}
}

func EncodeHTTP2Header(protoType ProtoType, rawDataLen int, dst []byte) (header []byte, padSize byte) {
	if cap(dst) < Http2HeaderLen {
		dst = make([]byte, Http2HeaderLen)
	} else {
		dst = dst[:Http2HeaderLen]
	}

	length := bytespool.Get(4)
	defer bytespool.MustPut(length)

	dataLen := uint32(rawDataLen)
	hasPadding := rawDataLen <= PaddingSize
	if hasPadding {
		ps := RandomBetween(MinPaddingSize, MaxPaddingSize)
		// padding len + raw data len + padding data len
		dataLen = 1 + uint32(rawDataLen) + uint32(ps)
		padSize = byte(ps)
	}
	binary.BigEndian.PutUint32(length, dataLen)

	// set length field
	copy(dst[:3], length[1:])
	// set frame type
	dst[3] = protoType.ToUint8()
	// set default flag
	dst[4] = 0x0
	if hasPadding { // data has padding field
		dst[4] = 0x8
	}

	// set stream identifier. note: this is temporary, will update in future
	binary.BigEndian.PutUint32(dst[5:Http2HeaderLen], uint32(rand.Int31()))

	return dst, padSize
}

// PayloadLen returns payload length in http2 header frame,
// panic if header's length not equals Http2HeaderLen
func PayloadLen(header []byte) int {
	if len(header) != Http2HeaderLen {
		panic("header length is invalid")
	}
	return int(header[0])<<16 | int(header[1])<<8 | int(header[2])
}

// HasPadding returns true if http2 header frame has padding field,
// panic if header's length not equals Http2HeaderLen
func HasPadding(header []byte) bool {
	if len(header) != Http2HeaderLen {
		panic("header length is invalid")
	}
	return header[4] == 0x8
}

func ProtoTypeFromHeader(header []byte) ProtoType {
	if len(header) != Http2HeaderLen {
		panic("header length is invalid")
	}
	return ParseProtoTypeFrom(header[3])
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
