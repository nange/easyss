package utils

import (
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// max addr: see socks5.go define
const maxaddr = 257

func NewHTTP2DataFrame(data []byte) []byte {
	// max http2 dataframe: 3 + 1 + 1 + 4 + 1 + 257)
	const maxframelen = 3 + 1 + 1 + 4 + 1 + maxaddr
	frame := make([]byte, maxframelen)

	datalen := len(data)
	paddinglen := maxaddr - datalen

	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, maxaddr)

	// set length field of data frame
	copy(frame[:3], length[1:])
	// set frame type to data
	frame[3] = 0x0

	datastart := 9
	// set padding flag
	if datalen < maxaddr {
		frame[4] = 0x08
		frame[9] = byte(paddinglen)
		datastart = 10
	}
	// set stream identifier. note: this is temporary, will update in future
	binary.BigEndian.PutUint32(frame[5:9], uint32(rand.Int31()))
	// set data
	copy(frame[datastart:datastart+datalen], data)

	return frame
}

func GetAddrFromHTTP2DataFrame(frame []byte) ([]byte, error) {
	length := int(frame[0])<<16 | int(frame[1])<<8 | int(frame[2])
	if length != maxaddr {
		return nil, errors.WithStack(errors.New(fmt.Sprintf("http2 data frame length:%v is invalid", length)))
	}
	if frame[3] != 0x0 {
		return nil, errors.WithStack(errors.New(fmt.Sprintf("http2 data frame type:%v is invalid", frame[3])))
	}

	padding := false
	paddinglen := 0
	if frame[4] == 0x08 {
		padding = true
		paddinglen = int(frame[9])
	}

	identifier := binary.BigEndian.Uint32(frame[5:9])
	log.Debugf("http2 data frame identifier: %v", identifier)

	if padding {
		return frame[10 : length-paddinglen], nil
	}

	return frame[9:length], nil
}
