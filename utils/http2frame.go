package utils

import (
	"encoding/binary"
	"math/rand"
)

func NewHTTP2DataFrame(data []byte) (header []byte, payload []byte) {
	header = make([]byte, 9)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, len(data))
	// set length field
	copy(header[:3], length[1:])
	// set frame type to data
	header[3] = 0x0
	// set default flag
	header[4] = 0x0

	// set stream identifier. note: this is temporary, will update in future
	binary.BigEndian.PutUint32(header[5:9], uint32(rand.Int31()))

	return header, data
}
