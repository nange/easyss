package dns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupIPV4From(t *testing.T) {
	ips, err := LookupIPV4From("119.29.29.29:53", "dnspod.cn")
	assert.Nil(t, err)
	assert.Greater(t, len(ips), 0)
}
