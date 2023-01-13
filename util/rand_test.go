package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandomBetween(t *testing.T) {
	for i := 0; i < 100; i++ {
		r1 := RandomBetween(64, 256)
		assert.GreaterOrEqual(t, r1, int64(64))
		assert.Less(t, r1, int64(256))
	}
}
