package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBytes(t *testing.T) {
	bytesPool := NewBytes(10)
	b := bytesPool.Get(5)
	assert.Len(t, b, 5)
	assert.Equal(t, cap(b), 10)
	bytesPool.Put(b)
}
