package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIP(t *testing.T) {
	assert.True(t, IsIP("127.0.0.1"))
	assert.False(t, IsIP("127.0.0"))

	assert.True(t, IsPrivateIP("192.168.0.1"))
	assert.False(t, IsPrivateIP(" "))

	assert.True(t, IsLoopbackIP("127.0.0.1"))
	assert.True(t, IsLoopbackIP("::1"))

	assert.True(t, IsIPV6("::0"))
	assert.False(t, IsIPV6("127.0.1"))
}
