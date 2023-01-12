package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeHTTP2DataFrameHeader(t *testing.T) {
	dst := make([]byte, 0, 10)
	header := EncodeHTTP2Header(ProtoTypeTCP, 20, dst)
	assert.Len(t, header, 9)
	assert.Equal(t, uint8(0), header[3])

	dst = nil
	header = EncodeHTTP2Header(ProtoTypeUDP, 20, dst)
	assert.Len(t, header, 9)
	assert.Equal(t, uint8(1), header[3])
}

func TestEncodeFINRstStreamHeader(t *testing.T) {
	header := EncodeFINRstStream(nil)
	assert.Len(t, header, 9)
	assert.Equal(t, uint8(7), header[3])
	assert.Equal(t, uint8(0), header[4])

	dst := make([]byte, 10)
	header = EncodeFINRstStream(dst)
	assert.Len(t, header, 9)
	assert.Equal(t, uint8(7), header[3])
	assert.Equal(t, uint8(0), header[4])
}

func TestEncodeACKRstStreamHeader(t *testing.T) {
	header := EncodeACKRstStream(nil)
	assert.Len(t, header, 9)
	assert.Equal(t, uint8(7), header[3])
	assert.Equal(t, uint8(1), header[4])

	dst := make([]byte, 10)
	header = EncodeACKRstStream(dst)
	assert.Len(t, header, 9)
	assert.Equal(t, uint8(7), header[3])
	assert.Equal(t, uint8(1), header[4])
}
