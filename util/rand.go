package util

import (
	"math/rand"
)

func RandomBetween(min, max int64) int64 {
	return rand.Int63n(max-min) + min
}
