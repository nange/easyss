package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIP(t *testing.T) {
	assert.True(t, IsIP("127.0.0.1"))
	assert.False(t, IsIP("127.0.0"))

	assert.True(t, IsLANIP("192.168.0.1"))
	assert.False(t, IsLANIP(" "))

	assert.False(t, IsLANIP("183.47.103.43"))

	assert.True(t, IsLoopbackIP("127.0.0.1"))
	assert.True(t, IsLoopbackIP("::1"))

	assert.True(t, IsIPV6("::0"))
	assert.False(t, IsIPV6("127.0.1"))
}

func TestLookupIPV4From(t *testing.T) {
	ips, err := LookupIPV4From("119.29.29.29:53", "dnspod.cn")
	assert.Nil(t, err)
	assert.Greater(t, len(ips), 0)
}
