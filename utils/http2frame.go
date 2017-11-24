package utils

import (
	"encoding/binary"
	"math/rand"
)

func NewHTTP2DataFrameHeader(datalen int) (header []byte) {
	header = make([]byte, 9)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(datalen))
	// set length field
	copy(header[:3], length[1:])
	// set frame type to data
	header[3] = 0x0
	// set default flag
	header[4] = 0x0

	// set stream identifier. note: this is temporary, will update in future
	binary.BigEndian.PutUint32(header[5:9], uint32(rand.Int31()))

	return header
}

func NewFINRstStreamHeader() (header []byte) {
	header = make([]byte, 9)
	binary.BigEndian.PutUint16(header[1:3], uint16(4))
	// set frame type to RST_STREAM
	header[3] = 0x7
	// set default flag
	header[4] = 0x0

	// set stream identifier. note: this is temporary, will update in future
	binary.BigEndian.PutUint32(header[5:9], uint32(rand.Int31()))

	return header
}

func NewACKRstStreamHeader() (header []byte) {
	header = make([]byte, 9)
	binary.BigEndian.PutUint16(header[1:3], uint16(4))
	// set frame type to RST_STREAM
	header[3] = 0x7
	// set default flag
	header[4] = 0x1

	// set stream identifier. note: this is temporary, will update in future
	binary.BigEndian.PutUint32(header[5:9], uint32(rand.Int31()))

	return header
}
