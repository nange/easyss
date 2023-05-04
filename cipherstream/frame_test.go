package cipherstream

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeHTTP2DataFrameHeader(t *testing.T) {
	dst := make([]byte, 0, 10)
	header, padSize := encodeHTTP2Header(FrameTypeData, FlagTCP, 20, dst)
	assert.Len(t, header, 9)
	assert.Equal(t, FlagTCP, header[4]&FlagTCP)
	assert.Greater(t, padSize, byte(0))

	dst = nil
	header, padSize = encodeHTTP2Header(FrameTypeData, FlagUDP, 200, dst)
	assert.Len(t, header, 9)
	assert.Equal(t, FlagUDP, header[4]&FlagUDP)
	assert.Equal(t, padSize, byte(0))
}
