package util

import (
	"encoding/binary"
	"math/rand"

	"github.com/nange/easyss/v2/util/bytespool"
)

const (
	Http2HeaderLen = 9
	PaddingSize    = 64
	MaxPaddingSize = 255
	MinPaddingSize = 64
)

type FrameType uint8

const (
	FrameTypeData    FrameType = 0x0
	FrameTypeRST     FrameType = 0x3
	FrameTypePing    FrameType = 0x6
	FrameTypeUnknown FrameType = 0xff
)

func ParseFrameTypeFrom(i uint8) FrameType {
	switch FrameType(i) {
	case FrameTypeData, FrameTypePing, FrameTypeRST:
		return FrameType(i)
	default:
		return FrameTypeUnknown
	}
}

func (ft FrameType) ToUint8() uint8 {
	return uint8(ft)
}

func (ft FrameType) String() string {
	switch ft {
	case FrameTypeData:
		return "data"
	case FrameTypePing:
		return "ping"
	case FrameTypeRST:
		return "rst"
	default:
		return "unknown"
	}
}

const FlagDefault uint8 = 0
const (
	FlagTCP uint8 = 1 << iota
	FlagUDP
	FlagICMP
	FlagPad
	FlagNeedACK
	FlagFIN
	FlagACK
)

func EncodeHTTP2Header(frameType FrameType, flag uint8, rawDataLen int, dst []byte) (header []byte, padSize byte) {
	if cap(dst) < Http2HeaderLen {
		dst = make([]byte, Http2HeaderLen)
	} else {
		dst = dst[:Http2HeaderLen]
	}

	length := bytespool.Get(4)
	defer bytespool.MustPut(length)

	dataLen := uint32(rawDataLen)
	needPad := rawDataLen <= PaddingSize
	if needPad {
		ps := RandomBetween(MinPaddingSize, MaxPaddingSize)
		// padding len + raw data len + padding data len
		dataLen += 1 + uint32(ps)
		padSize = byte(ps)
	}
	binary.BigEndian.PutUint32(length, dataLen)

	// set length field
	copy(dst[:3], length[1:])
	// set frame type
	dst[3] = frameType.ToUint8()
	// set default flag
	dst[4] = flag
	if needPad { // data has pad field
		dst[4] |= FlagPad
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

// HasPad returns true if http2 header frame has pad field,
// panic if header's length not equals Http2HeaderLen
func HasPad(header []byte) bool {
	if len(header) != Http2HeaderLen {
		panic("header length is invalid")
	}
	return header[4]&FlagPad == FlagPad
}

func FrameTypeFromHeader(header []byte) FrameType {
	if len(header) != Http2HeaderLen {
		panic("header length is invalid")
	}
	return ParseFrameTypeFrom(header[3])
}

func IsDataFrame(header []byte) bool {
	if len(header) != Http2HeaderLen {
		panic("header length is invalid")
	}
	return FrameTypeFromHeader(header) == FrameTypeData
}

func IsPingFrame(header []byte) bool {
	if len(header) != Http2HeaderLen {
		panic("header length is invalid")
	}
	return FrameTypeFromHeader(header) == FrameTypePing
}

func IsRSTFINFrame(header []byte) bool {
	if len(header) != Http2HeaderLen {
		panic("header length is invalid")
	}
	return FrameTypeFromHeader(header) == FrameTypeRST && header[4]&FlagFIN == FlagFIN
}

func IsRSTACKFrame(header []byte) bool {
	if len(header) != Http2HeaderLen {
		panic("header length is invalid")
	}
	return FrameTypeFromHeader(header) == FrameTypeRST && header[4]&FlagACK == FlagACK
}

func IsTCPProto(header []byte) bool {
	if len(header) != Http2HeaderLen {
		panic("header length is invalid")
	}
	return header[4]&FlagTCP == FlagTCP
}

func IsUDPProto(header []byte) bool {
	if len(header) != Http2HeaderLen {
		panic("header length is invalid")
	}
	return header[4]&FlagUDP == FlagUDP
}

func IsNeedACK(header []byte) bool {
	if len(header) != Http2HeaderLen {
		panic("header length is invalid")
	}
	return header[4]&FlagNeedACK == FlagNeedACK
}
